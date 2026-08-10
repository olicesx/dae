package control

import (
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/olicesx/quic-go"
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

// Transient write errors are tolerated up to writeSoftErrorThreshold: the
// endpoint survives and callers can identify the dropped datagram via
// isUdpEndpointWriteTolerated. A successful write resets the counter.
func TestUdpEndpointWriteToToleratesTransientErrors(t *testing.T) {
	sentinel := errors.New("boom")
	var calls int
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			calls++
			if calls <= writeSoftErrorThreshold {
				return 0, sentinel
			}
			return len(p), nil
		},
	}
	ue := newTestEndpoint(mock)
	for i := 1; i <= writeSoftErrorThreshold; i++ {
		_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
		if !errors.Is(err, sentinel) {
			t.Fatalf("attempt %d: expected sentinel error, got: %v", i, err)
		}
		if !isUdpEndpointWriteTolerated(err) {
			t.Fatalf("attempt %d: expected tolerated error, got: %v", i, err)
		}
		if ue.dead.Load() {
			t.Fatalf("attempt %d: endpoint must survive tolerated errors", i)
		}
	}
	// After the transient window a write succeeds and resets the counter.
	if _, err := ue.WriteTo([]byte("ok"), "1.2.3.4:53"); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if got := ue.writeSoftErrorCount.Load(); got != 0 {
		t.Fatalf("expected write soft error counter reset, got %d", got)
	}
}

// A datagram send-queue timeout signals a stalled transport, not a transient
// error: it must retire immediately. Counting it toward the tolerated
// threshold is unsafe — a later enqueue (which is not a peer ACK) would reset
// the counter and let a half-dead transport dodge retirement forever.
func TestUdpEndpointWriteToRetiresOnDatagramQueueTimeout(t *testing.T) {
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, quic.ErrDatagramQueueFullTimeout
		},
	}
	ue := newTestEndpoint(mock)
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !errors.Is(err, quic.ErrDatagramQueueFullTimeout) {
		t.Fatalf("expected datagram queue timeout error, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must retire on a datagram send-queue timeout")
	}
}

// A write error beyond the tolerated threshold must retire the endpoint and
// surface the underlying error (not the tolerated wrapper).
func TestUdpEndpointWriteToRetiresOnPersistentError(t *testing.T) {
	sentinel := errors.New("boom")
	mock := &mockPacketConn{
		writeToFn: func(p []byte, addr string) (int, error) {
			return 0, sentinel
		},
	}
	ue := newTestEndpoint(mock)
	for i := 0; i < writeSoftErrorThreshold; i++ {
		if _, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53"); !isUdpEndpointWriteTolerated(err) {
			t.Fatalf("attempt %d: expected tolerated error, got: %v", i+1, err)
		}
	}
	_, err := ue.WriteTo([]byte("hello world"), "1.2.3.4:53")
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got: %v", err)
	}
	if !ue.dead.Load() {
		t.Fatal("endpoint must be retired after the tolerated threshold is exceeded")
	}
}

// deadlineRecordingPacketConn records whether SetWriteDeadline was called and
// optionally implements TransportLifecycle (a QUIC-backed transport).
type deadlineRecordingPacketConn struct {
	writeToFn              func(p []byte, addr string) (int, error)
	setWriteDeadlineCalled bool
	transportDone          <-chan struct{}
}

func (c *deadlineRecordingPacketConn) Read(b []byte) (int, error)  { return 0, io.EOF }
func (c *deadlineRecordingPacketConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *deadlineRecordingPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (c *deadlineRecordingPacketConn) WriteTo(p []byte, addr string) (int, error) {
	if c.writeToFn != nil {
		return c.writeToFn(p, addr)
	}
	return len(p), nil
}
func (c *deadlineRecordingPacketConn) Close() error                      { return nil }
func (c *deadlineRecordingPacketConn) SetDeadline(t time.Time) error     { return nil }
func (c *deadlineRecordingPacketConn) SetReadDeadline(t time.Time) error { return nil }
func (c *deadlineRecordingPacketConn) SetWriteDeadline(t time.Time) error {
	c.setWriteDeadlineCalled = true
	return nil
}
func (c *deadlineRecordingPacketConn) TransportDone() <-chan struct{} { return c.transportDone }

// A QUIC-backed transport (TransportLifecycle implemented, non-nil channel)
// must NOT arm a write deadline: datagram send-queue backpressure is a normal
// congestion signal, not a dead peer (xray/sing-box treat it the same way),
// and connection death is handled by the transport lifecycle watcher.
func TestArmWriteDeadlineSkipsTransportLifecycleConn(t *testing.T) {
	conn := &deadlineRecordingPacketConn{transportDone: make(chan struct{})}
	ue := newTestEndpoint(conn)

	ue.armWriteDeadline(time.Now())

	if conn.setWriteDeadlineCalled {
		t.Fatal("armWriteDeadline must not call SetWriteDeadline on a TransportLifecycle conn")
	}
	if ue.writeDeadlineArmedAtNano.Load() != 0 {
		t.Fatal("writeDeadlineArmedAtNano must not be armed for a TransportLifecycle conn")
	}
}

// Transports without a transport-lifecycle channel keep the legacy
// write-deadline behaviour for dead-peer detection.
func TestArmWriteDeadlineStillArmsPlainConn(t *testing.T) {
	conn := &deadlineRecordingPacketConn{}
	ue := newTestEndpoint(conn)

	ue.armWriteDeadline(time.Now())

	if !conn.setWriteDeadlineCalled {
		t.Fatal("armWriteDeadline must keep arming plain (non-lifecycle) conns")
	}
	if ue.writeDeadlineArmedAtNano.Load() == 0 {
		t.Fatal("writeDeadlineArmedAtNano should be armed for a plain conn")
	}
}
