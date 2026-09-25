package control

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

// mockProxiedConn wraps a net.Conn with a non-TCP identity so that unwrapRelayTCPConn
// returns false, forcing the traffic through the proxied relay pipeline (userspace copy loop).
type mockProxiedConn struct {
	net.Conn
	writeCalls atomic.Int64
}

func (m *mockProxiedConn) Write(b []byte) (int, error) {
	m.writeCalls.Add(1)
	return m.Conn.Write(b)
}

func (m *mockProxiedConn) CloseWrite() error {
	if cw, ok := m.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// BenchmarkProxiedTCPRelay measures throughput and allocations of the userspace relay path
// handling proxied traffic between an ingress connection and an egress proxy connection.
func BenchmarkProxiedTCPRelay(b *testing.B) {
	const chunkSize = 32 << 10
	const totalChunks = 32 // 1MB per benchmark iteration
	payload := make([]byte, chunkSize*totalChunks)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))

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
			defer c.Close()
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

		// Client writes payload to ingress
		clientConn, ingressRaw := net.Pipe()
		ingress := &mockProxiedConn{Conn: ingressRaw}

		go func() {
			_, _ = clientConn.Write(payload)
			_ = clientConn.Close()
		}()

		b.StartTimer()
		_ = RelayTCPContextWithRecords(context.Background(), ingress, egress, nil, nil)
		<-serverDone
		_ = egressRaw.Close()
		_ = ingressRaw.Close()
		_ = ln.Close()
	}
}

// BenchmarkProxiedGatherWrite measures the efficiency of delivering gathered prefix segments
// to an egress proxy connection (simulating initial request + TLS Client Hello).
func BenchmarkProxiedGatherWrite(b *testing.B) {
	prefix1 := []byte{0x05, 0x01, 0x00}
	prefix2 := []byte{0x05, 0x01, 0x00, 0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb}
	payload := make([]byte, 1024)

	segs := [][]byte{prefix1, prefix2, payload}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

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

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		proxyConn := &mockProxiedConn{Conn: raw}

		_, _ = relayGatherWriteTo(proxyConn, segs)
		_ = raw.Close()
	}
}

func TestProxiedGatherWriteCoalescesToSingleWrite(t *testing.T) {
	prefix1 := []byte{0x05, 0x01, 0x00}
	prefix2 := []byte{0x05, 0x01, 0x00, 0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb}
	payload := make([]byte, 1024)
	segs := [][]byte{prefix1, prefix2, payload}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 2048)
		for {
			_, err := c.Read(buf)
			if err != nil {
				break
			}
		}
		_ = c.Close()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	proxyConn := &mockProxiedConn{Conn: raw}
	n, err := relayGatherWriteTo(proxyConn, segs)
	if err != nil {
		t.Fatalf("relayGatherWriteTo: %v", err)
	}
	expectedLen := len(prefix1) + len(prefix2) + len(payload)
	if n != expectedLen {
		t.Fatalf("written %d, want %d", n, expectedLen)
	}
	if calls := proxyConn.writeCalls.Load(); calls != 1 {
		t.Fatalf("expected exactly 1 coalesced Write call, got %d", calls)
	}
}
