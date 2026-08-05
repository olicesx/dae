package control

import (
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// mockPacketConn is a minimal netproxy.PacketConn whose WriteTo result is
// scriptable per test.
type mockPacketConn struct {
	writeToFn func(p []byte, addr string) (int, error)
}

func (m *mockPacketConn) Read(b []byte) (int, error)  { return 0, io.EOF }
func (m *mockPacketConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (m *mockPacketConn) WriteTo(p []byte, addr string) (int, error) {
	if m.writeToFn != nil {
		return m.writeToFn(p, addr)
	}
	return len(p), nil
}
func (m *mockPacketConn) Close() error                       { return nil }
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func newTestEndpoint(conn netproxy.PacketConn) *UdpEndpoint {
	return &UdpEndpoint{conn: conn}
}

// The ss/vmess regression: protocol dialers that return the encapsulated
// datagram size (len(payload)+overhead) must NOT be treated as a short write.
func TestUdpEndpointWriteToAcceptsOverheadReturn(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			// shadowsocks AEAD returns len(payload)+39 (salt+metadata+tag)
			return len(p) + 39, nil
		},
	}
	ue := newTestEndpoint(mock)
	n, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err != nil {
		t.Fatalf("WriteTo with overhead return should succeed, got err: %v", err)
	}
	if n != len("hello world")+39 {
		t.Fatalf("expected encapsulated length %d, got %d", len("hello world")+39, n)
	}
	if ue.dead.Load() {
		t.Fatal("endpoint must not be retired when WriteTo returns n > len(b)")
	}
	if !ue.hasSent.Load() {
		t.Fatal("hasSent should be set after a successful write")
	}
}

// A genuine short write (n < len(b)) must still retire the endpoint.
func TestUdpEndpointWriteToRetiresOnRealShortWrite(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return len(p) - 1, nil
		},
	}
	ue := newTestEndpoint(mock)
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if err == nil || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must be retired on a real short write")
	}
}

// A write error must retire the endpoint and surface the error.
func TestUdpEndpointWriteToRetiresOnError(t *testing.T) {
	sentinel := errors.New("boom")
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, sentinel
		},
	}
	ue := newTestEndpoint(mock)
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must be retired on write error")
	}
}
