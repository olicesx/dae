//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestUDPGSO_CmsgBuilding(t *testing.T) {
	segmentSize := uint16(1400)
	cmsg := BuildUDPGSOControlMsg(segmentSize)
	require.NotEmpty(t, cmsg)

	parsed, err := unix.ParseSocketControlMessage(cmsg)
	require.NoError(t, err)
	require.Len(t, parsed, 1)

	hdr := parsed[0].Header
	require.Equal(t, int32(SolUDP), hdr.Level)
	require.Equal(t, int32(UDPSEGMENT), hdr.Type)
}

func TestUDPGRO_SplitPayload(t *testing.T) {
	// Case 1: Payload smaller than segmentSize
	payload := []byte("hello")
	segs := SplitUDPGROPayload(payload, 1400)
	require.Len(t, segs, 1)
	require.Equal(t, payload, segs[0])

	// Case 2: Multi-segment payload
	seg1 := bytes.Repeat([]byte("A"), 1000)
	seg2 := bytes.Repeat([]byte("B"), 1000)
	seg3 := bytes.Repeat([]byte("C"), 400)
	combined := append(append(seg1, seg2...), seg3...)

	segs = SplitUDPGROPayload(combined, 1000)
	require.Len(t, segs, 3)
	require.Equal(t, seg1, segs[0])
	require.Equal(t, seg2, segs[1])
	require.Equal(t, seg3, segs[2])
}

func TestUDPGSO_LoopbackTransmission(t *testing.T) {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", serverAddr)
	require.NoError(t, err)
	defer serverConn.Close()

	// Enable UDP_GRO on receiver
	_ = EnableUDPGRO(serverConn)

	clientAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	clientConn, err := net.ListenUDP("udp", clientAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Probe GSO capability
	gsoSupported := ProbeUDPGSO(clientConn)
	t.Logf("Kernel UDP GSO supported: %v", gsoSupported)

	rawClient, err := clientConn.SyscallConn()
	require.NoError(t, err)

	destPort := serverConn.LocalAddr().(*net.UDPAddr).Port
	target := &unix.SockaddrInet4{
		Port: destPort,
		Addr: [4]byte{127, 0, 0, 1},
	}

	segSize := uint16(500)
	payload := bytes.Repeat([]byte("X"), int(segSize)*3) // 3 segments

	n, err := WriteUDPGSO(rawClient, payload, segSize, target)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	// Read from server side
	buf := make([]byte, 65535)
	oob := make([]byte, 1024)

	rn, oobn, _, _, err := serverConn.ReadMsgUDP(buf, oob)
	require.NoError(t, err)
	require.Positive(t, rn)

	// Check if GRO aggregated or delivered
	groSegSize, hasGRO := ParseUDPGRO(oob[:oobn])
	t.Logf("Received %d bytes (GRO enabled: %v, segSize: %d)", rn, hasGRO, groSegSize)
}

func BenchmarkUDP_TransmissionModes(b *testing.B) {
	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	serverConn, _ := net.ListenUDP("udp", serverAddr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_, _, err := serverConn.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	clientConn, _ := net.ListenUDP("udp", clientAddr)

	destPort := serverConn.LocalAddr().(*net.UDPAddr).Port
	target := &unix.SockaddrInet4{
		Port: destPort,
		Addr: [4]byte{127, 0, 0, 1},
	}
	rawClient, _ := clientConn.SyscallConn()

	const segSize = 1400
	const batchSegments = 32
	singlePayload := bytes.Repeat([]byte("U"), segSize)
	gsoPayload := bytes.Repeat([]byte("U"), segSize*batchSegments) // 44.8 KiB

	b.Run("Standard_Sendmsg_32_Times", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 0; j < batchSegments; j++ {
				_ = rawClient.Write(func(fd uintptr) bool {
					_, err := unix.SendmsgN(int(fd), singlePayload, nil, target, 0)
					return err != unix.EAGAIN
				})
			}
		}
	})

	b.Run("UDPGSO_Single_Sendmsg", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = WriteUDPGSO(rawClient, gsoPayload, segSize, target)
		}
	})

	_ = clientConn.Close()
	_ = serverConn.Close()
	wg.Wait()
}
