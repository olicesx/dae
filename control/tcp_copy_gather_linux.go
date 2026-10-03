//go:build linux

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

var (
	// relayWritevFunc is the test seam over unix.Writev: the partial-write
	// advancement and EAGAIN re-entry of relayWritevAll are pinned by tests
	// that script its results.
	relayWritevFunc = unix.Writev
)

const relayGatherInlineSegmentCap = 8

func relayTakeSourceSegments(src netproxy.Conn, scratch *[relayGatherInlineSegmentCap][]byte) [][]byte {
	if segmentSource, ok := src.(relaySegmentSource); ok {
		segments := relayNonEmptySegments(segmentSource.TakeRelaySegments())
		if len(segments) > 0 {
			return segments
		}
	}
	if prefixSource, ok := src.(relayPrefixSource); ok {
		prefix := prefixSource.TakeRelayPrefix()
		if len(prefix) > 0 {
			scratch[0] = prefix
			return scratch[:1]
		}
	}
	return nil
}

func relayBuildWriteSegments(prefixSegs [][]byte, body []byte, scratch *[relayGatherInlineSegmentCap + 1][]byte) [][]byte {
	if len(prefixSegs) == 0 {
		if len(body) == 0 {
			return nil
		}
		scratch[0] = body
		return scratch[:1]
	}

	extra := 0
	if len(body) > 0 {
		extra = 1
	}
	total := len(prefixSegs) + extra

	if total <= len(scratch) {
		copy(scratch[:], prefixSegs)
		if extra == 1 {
			scratch[len(prefixSegs)] = body
		}
		return scratch[:total]
	}

	if extra == 0 {
		return prefixSegs
	}

	writeSegs := make([][]byte, 0, total)
	writeSegs = append(writeSegs, prefixSegs...)
	writeSegs = append(writeSegs, body)
	return writeSegs
}

func tryRelayGatherWrite(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, record func(int64), onActive func(int64)) (written int64, err error, ok bool) {
	record = normalizeTrafficRecord(record)
	onActive = normalizeTrafficRecord(onActive)
	var sourceSegScratch [relayGatherInlineSegmentCap][]byte
	segments := relayTakeSourceSegments(src, &sourceSegScratch)
	if len(segments) == 0 {
		return 0, nil, false
	}
	bufPtr := relayCopyBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayCopyBufferPool.Put(bufPtr)

	prefixLen := 0
	for _, seg := range segments {
		prefixLen += len(seg)
	}

	var (
		body    []byte
		readErr error
	)
	var writeSegScratch [relayGatherInlineSegmentCap + 1][]byte
	var writeSegs [][]byte
	if prefixLen < len(buf) {
		// The taken segments alias the source's bufio/sniffer buffer and are
		// only valid until the next read of src, so the probe read below must
		// never leave them live: copy them into the pooled buffer first and
		// hand the write one contiguous prefix+body slice.
		off := 0
		for _, seg := range segments {
			off += copy(buf[off:], seg)
		}
		if srcTCP, ok := relayGatherWriteTCPConn(src); ok {
			pending, perr := tcpConnHasPendingReadData(srcTCP)
			if perr != nil {
				return 0, perr, true
			}
			if pending {
				nr, er := src.Read(buf[off:])
				if nr > 0 {
					body = buf[off : off+nr]
				}
				readErr = er
			}
		}
		writeSegScratch[0] = buf[:len(body)+off]
		writeSegs = writeSegScratch[:1]
	} else {
		// A prefix too large for the pooled buffer is written as-is and the
		// probe read is skipped this round: reading src now would invalidate
		// the aliased segments. The steady loop picks the rest up next.
		writeSegs = relayBuildWriteSegments(segments, nil, &writeSegScratch)
	}

	nw, err := relayGatherWriteTo(dst, writeSegs)
	written += int64(nw)
	if nw > 0 {
		onActive(int64(nw))
		record(int64(nw))
	}
	if err != nil {
		return written, err, true
	}

	if readErr != nil {
		if readErr == io.EOF {
			return written, nil, true
		}
		return written, readErr, true
	}

	if continuationSource, ok := src.(relayContinuationSource); ok {
		// Check context cancellation. relayCore.run ensures ctx is never nil.
		if cerr := ctx.Err(); cerr != nil {
			return written, cerr, true
		}
		n, err := continuationSource.CopyRelayRemainder(ctx, dst, buf, record, onActive)
		return written + n, err, true
	}

	n, err := relayCopyLoop(ctx, dst, src, buf, record, onActive)
	return written + n, err, true
}

func relayGatherWriteTCPConn(conn netproxy.Conn) (*net.TCPConn, bool) {
	return unwrapRelayTCPConn(conn)
}

func relayGatherWriteTo(dst netproxy.Conn, segs [][]byte) (written int, err error) {
	if dstTCP, ok := unwrapRelayTransparentTCPConn(dst); ok {
		rawConn, err := dstTCP.SyscallConn()
		if err != nil {
			return 0, err
		}
		return relayWritevAll(rawConn, segs)
	}

	segments := relayNonEmptySegments(segs)
	if len(segments) == 0 {
		return 0, nil
	}

	if len(segments) == 1 {
		return dst.Write(segments[0])
	}

	// For proxied connections (wrapped interfaces), coalesce multiple segments
	// into a single write buffer: this avoids multi-packet fragmentation and
	// repeated AEAD crypto framing. Only batches up to relayCopyBufferSize
	// (32 KiB) coalesce here; a larger batch (the steady loop gathers up to
	// 128 KiB) falls through to net.Buffers.WriteTo, which writes per segment —
	// functionally fine, and the fork's FlushConn re-coalesces at the TLS
	// layer, but it is not the single-write shape the small case gets.
	totalLen := 0
	for _, seg := range segments {
		totalLen += len(seg)
	}

	if totalLen <= relayCopyBufferSize {
		bufPtr := relayCopyBufferPool.Get().(*[]byte)
		coalesced := (*bufPtr)[:totalLen]
		offset := 0
		for _, seg := range segments {
			copy(coalesced[offset:], seg)
			offset += len(seg)
		}
		n, err := dst.Write(coalesced)
		relayCopyBufferPool.Put(bufPtr)
		return n, err
	}

	buffers := net.Buffers(segments)
	n, err := buffers.WriteTo(dst)
	return int(n), err
}

func relayWritevAll(rawConn syscall.RawConn, segs [][]byte) (written int, err error) {
	segments := relayNonEmptySegments(segs)
	if len(segments) == 0 {
		return 0, nil
	}

	var writeErr error
	err = rawConn.Write(func(fd uintptr) bool {
		for len(segments) > 0 {
			n, err := relayWritevFunc(int(fd), segments)
			if n > 0 {
				written += n
				segments = relayAdvanceSegments(segments, n)
			}
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					return false
				}
				writeErr = err
				return true
			}
			if n == 0 {
				writeErr = io.ErrShortWrite
				return true
			}
		}
		return true
	})
	if err != nil {
		return written, err
	}
	if writeErr != nil {
		return written, writeErr
	}
	return written, nil
}

func relayNonEmptySegments(segs [][]byte) [][]byte {
	filtered := segs[:0]
	for _, seg := range segs {
		if len(seg) == 0 {
			continue
		}
		filtered = append(filtered, seg)
	}
	return filtered
}

func relayAdvanceSegments(segs [][]byte, n int) [][]byte {
	for len(segs) > 0 && n > 0 {
		if n >= len(segs[0]) {
			n -= len(segs[0])
			segs = segs[1:]
			continue
		}
		segs[0] = segs[0][n:]
		return segs
	}
	return segs
}
func tcpConnHasPendingReadData(conn *net.TCPConn) (bool, error) {
	pending, err := tcpConnPendingBytes(conn)
	if err != nil {
		return false, err
	}
	return pending > 0, nil
}
