//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// SolUDP is the socket level for UDP (IPPROTO_UDP = 17).
	SolUDP = 17

	// UDPGRO is the socket option (SOL_UDP, 104) to enable UDP Generic Receive Offload.
	UDPGRO = 104

	// UDPSEGMENT is the socket option / cmsg type (SOL_UDP, 103) for Generic Segmentation Offload.
	UDPSEGMENT = 103
)

// EnableUDPGRO enables UDP Generic Receive Offload on the given UDP socket.
// When enabled, Linux kernel drivers aggregate multiple back-to-back UDP packets
// of the same flow into a single large datagram with a UDP_GRO control message
// specifying the original segment size.
func EnableUDPGRO(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw conn for UDP_GRO: %w", err)
	}

	var sockErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), SolUDP, UDPGRO, 1)
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	if sockErr != nil {
		return fmt.Errorf("setsockopt UDP_GRO: %w", sockErr)
	}
	return nil
}

// ProbeUDPGSO checks whether the Linux kernel and current socket support UDP Generic Segmentation Offload.
func ProbeUDPGSO(conn *net.UDPConn) bool {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return false
	}

	var supported bool
	_ = rawConn.Control(func(fd uintptr) {
		// Attempting to read UDP_SEGMENT socket option; supported kernels (5.0+) return 0 or the current value.
		_, err := unix.GetsockoptInt(int(fd), SolUDP, UDPSEGMENT)
		supported = (err == nil)
	})
	return supported
}

// BuildUDPGSOControlMsg builds a control message (cmsg) containing the UDP_SEGMENT header
// indicating that the kernel should slice the aggregate payload into segments of segmentSize.
func BuildUDPGSOControlMsg(segmentSize uint16) []byte {
	cmsgLen := unix.CmsgSpace(2)
	oob := make([]byte, cmsgLen)
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	cmsg.Level = SolUDP
	cmsg.Type = UDPSEGMENT
	cmsg.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.SizeofCmsghdr:], segmentSize)
	return oob
}

// WriteUDPGSO sends a contiguous buffer composed of multiple logical UDP datagrams
// using a single sendmsg system call with UDP_SEGMENT, allowing the kernel/NIC
// to perform hardware/software segmentation.
func WriteUDPGSO(rawConn syscall.RawConn, payload []byte, segmentSize uint16, to unix.Sockaddr) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	if segmentSize == 0 || len(payload) <= int(segmentSize) {
		// Fallback to plain sendmsg without GSO if single segment
		var n int
		var sockErr error
		err := rawConn.Write(func(fd uintptr) bool {
			n, sockErr = unix.SendmsgN(int(fd), payload, nil, to, 0)
			return sockErr != unix.EAGAIN && sockErr != unix.EWOULDBLOCK
		})
		if err != nil {
			return 0, err
		}
		return n, sockErr
	}

	oob := BuildUDPGSOControlMsg(segmentSize)

	var n int
	var sockErr error
	err := rawConn.Write(func(fd uintptr) bool {
		n, sockErr = unix.SendmsgN(int(fd), payload, oob, to, 0)
		return sockErr != unix.EAGAIN && sockErr != unix.EWOULDBLOCK
	})
	if err != nil {
		return 0, err
	}
	return n, sockErr
}

// ParseUDPGRO parses control messages (OOB) received from a socket with UDP_GRO enabled.
// Returns the individual segment size and true if a UDP_GRO control message is present.
func ParseUDPGRO(oob []byte) (int, bool) {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, false
	}

	for _, cmsg := range cmsgs {
		if cmsg.Header.Level == SolUDP && cmsg.Header.Type == UDPGRO {
			if len(cmsg.Data) >= 2 {
				segSize := int(binary.NativeEndian.Uint16(cmsg.Data[:2]))
				return segSize, true
			}
		}
	}
	return 0, false
}

// SplitUDPGROPayload slices an aggregate UDP_GRO payload into individual datagram views
// based on the segmentSize received from OOB. Zero allocations are made for payloads.
func SplitUDPGROPayload(payload []byte, segmentSize int) [][]byte {
	if segmentSize <= 0 || len(payload) <= segmentSize {
		return [][]byte{payload}
	}

	numSegs := (len(payload) + segmentSize - 1) / segmentSize
	segments := make([][]byte, 0, numSegs)

	for len(payload) > 0 {
		take := segmentSize
		if take > len(payload) {
			take = len(payload)
		}
		segments = append(segments, payload[:take])
		payload = payload[take:]
	}

	return segments
}
