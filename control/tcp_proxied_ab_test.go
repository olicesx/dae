package control

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// trackingConn counts individual Write calls to verify packet coalescing
type trackingConn struct {
	net.Conn
	writeCount   atomic.Int64
	bytesWritten atomic.Int64
}

func (t *trackingConn) Write(b []byte) (int, error) {
	t.writeCount.Add(1)
	t.bytesWritten.Add(int64(len(b)))
	return t.Conn.Write(b)
}

// TestAB_GatherWriteCoalescing compares legacy uncoalesced vs optimized coalesced
// write behavior for proxied connections.
func TestAB_GatherWriteCoalescing(t *testing.T) {
	// Simulate: SOCKS5 header (3 bytes) + Target Addr (18 bytes) + TLS ClientHello (512 bytes)
	prefix1 := []byte{0x05, 0x01, 0x00}
	prefix2 := []byte{0x05, 0x01, 0x00, 0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb}
	payload := make([]byte, 512)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	segs := [][]byte{prefix1, prefix2, payload}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				buf := make([]byte, 2048)
				for {
					_, err := conn.Read(buf)
					if err != nil {
						break
					}
				}
				_ = conn.Close()
			}(c)
		}
	}()

	// 1. Optimized Path (relayGatherWriteTo)
	rawOpt, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rawOpt.Close() }()

	trackedOpt := &trackingConn{Conn: rawOpt}
	nOpt, err := relayGatherWriteTo(trackedOpt, segs)
	if err != nil {
		t.Fatalf("relayGatherWriteTo: %v", err)
	}

	expectedLen := len(prefix1) + len(prefix2) + len(payload)
	if nOpt != expectedLen {
		t.Fatalf("opt written = %d, want %d", nOpt, expectedLen)
	}

	optWrites := trackedOpt.writeCount.Load()
	t.Logf("[A/B GatherWrite] Optimized Write calls: %d (coalesced into exactly 1 packet)", optWrites)
	if optWrites != 1 {
		t.Fatalf("want 1 coalesced write, got %d", optWrites)
	}

	// 2. Legacy Uncoalesced Simulation (net.Buffers slice-by-slice write)
	rawLeg, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rawLeg.Close() }()

	trackedLeg := &trackingConn{Conn: rawLeg}
	legacyBuffers := net.Buffers(segs)
	nLeg, err := legacyBuffers.WriteTo(trackedLeg)
	if err != nil {
		t.Fatalf("legacyBuffers.WriteTo: %v", err)
	}
	if int(nLeg) != expectedLen {
		t.Fatalf("legacy written = %d, want %d", nLeg, expectedLen)
	}

	legacyWrites := trackedLeg.writeCount.Load()
	t.Logf("[A/B GatherWrite] Legacy Write calls: %d (split into %d fragmented packets)", legacyWrites, len(segs))
	if legacyWrites <= 1 {
		t.Fatalf("legacy simulation should have fragmented across multiple slices, got %d", legacyWrites)
	}
}

// BenchmarkAB_ProxiedRelayThroughput benchmarks moving 4MB of data across proxied relay
func BenchmarkAB_ProxiedRelayThroughput(b *testing.B) {
	const totalSize = 4 << 20 // 4MB
	payload := make([]byte, totalSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ReportAllocs()
	b.SetBytes(int64(totalSize))

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}

		serverDone := make(chan struct{})
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			buf := make([]byte, 64<<10)
			for {
				_, rerr := c.Read(buf)
				if rerr != nil {
					break
				}
			}
			close(serverDone)
		}()

		egressRaw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		egress := &mockProxiedConn{Conn: egressRaw}

		clientConn, ingressRaw := net.Pipe()
		ingress := &mockProxiedConn{Conn: ingressRaw}

		go func() {
			_, _ = clientConn.Write(payload)
			_ = clientConn.Close()
		}()

		b.StartTimer()
		start := time.Now()
		_ = RelayTCPContextWithRecords(context.Background(), ingress, egress, nil, nil)
		<-serverDone
		elapsed := time.Since(start)
		_ = elapsed

		_ = egressRaw.Close()
		_ = ingressRaw.Close()
		_ = ln.Close()
	}
}
