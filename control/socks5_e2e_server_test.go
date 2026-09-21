/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// In-test SOCKS5 server used by the real-transport reply-drought e2e tests.
//
// The server is adapted from the outbound fork's own protocol e2e suite
// (github.com/daeuniverse/outbound protocol/socks5 e2e_test.go, module pin
// olicesx/outbound ...cc86ced2e683), which already proves the fork's socks5
// client interoperates with an RFC 1928 / RFC 1929 server. Only the UDP
// ASSOCIATE handler differs: it uses one egress socket per association on an
// explicitly allocated loopback port so a fresh association necessarily
// presents a fresh forwarding identity.

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// startUDPEchoTarget echoes datagrams back to their sender.
// readFullOrDead wraps io.ReadFull with the test deadline.
func readFullOrDead(t *testing.T, c net.Conn, buf []byte) error {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	_, err := io.ReadFull(c, buf)
	return err
}

// writeFullOrDead wraps a bounded write for the server side.
func writeFullOrDead(t *testing.T, c net.Conn, b []byte) error {
	t.Helper()
	if err := c.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	_, err := c.Write(b)
	return err
}

// ---- in-test socks5 server (independent wire-format implementation) ----

// Wire constants for RFC 1928 and RFC 1929, spelled out locally so the test
// server can never accidentally lean on the client's own constants.
const (
	socks5TestVer                    byte = 5
	socks5TestAuthNone               byte = 0x00
	socks5TestAuthPassword           byte = 0x02
	socks5TestAuthNoAcceptable       byte = 0xff
	socks5TestPasswordSubNegotiation byte = 1 // RFC 1929 VER inside the auth exchange
	socks5TestCmdConnect             byte = 1
	socks5TestCmdUDPAssociate        byte = 3
	socks5TestAtypIPv4               byte = 1
	socks5TestAtypDomain             byte = 3
	socks5TestAtypIPv6               byte = 4
	socks5TestRepSuccess             byte = 0
	socks5TestRepGeneralFailure      byte = 1
)

// socks5ServerOptions configures the in-test SOCKS5 server.
type socks5ServerOptions struct {
	// requireAuth offers only method 0x02 (username/password, RFC 1929).
	// A client offering no usable method gets 0xff and a close.
	requireAuth bool
	username    string
	password    string
	// connectReply != 0 makes every CONNECT request get this reply code
	// instead of a real relay (error-path coverage).
	connectReply byte
}

type socks5TestServer struct {
	ln   net.Listener
	opts socks5ServerOptions
	// udpRedirect maps a requested UDP destination to the address the server
	// really forwards to; replies still report the requested address, exactly
	// like a proxy that forwards through its own mapping.
	udpRedirect map[netip.AddrPort]netip.AddrPort

	mu            sync.Mutex
	chosenMethod  byte
	authUser      string
	authPass      string
	downstreamEOF chan struct{}
	eofOnce       sync.Once
}

// startSocks5Server runs the in-test SOCKS5 server on a real loopback
// listener and returns it (use addr() for the client-facing address).
func startSocks5Server(t *testing.T, opts socks5ServerOptions) *socks5TestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &socks5TestServer{
		ln:            ln,
		opts:          opts,
		downstreamEOF: make(chan struct{}),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serveSocks5Conn(t, c)
		}
	}()
	return srv
}

func (srv *socks5TestServer) addr() string { return srv.ln.Addr().String() }

func (srv *socks5TestServer) recordMethod(method byte) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.chosenMethod = method
}

func (srv *socks5TestServer) recordAuth(user, pass string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.authUser, srv.authPass = user, pass
}

func (srv *socks5TestServer) markDownstreamEOF() {
	srv.eofOnce.Do(func() { close(srv.downstreamEOF) })
}

// readSocks5TestAddress decodes ATYP + address + port (RFC 1928 section 5)
// from the stream.
func readSocks5TestAddress(t *testing.T, c net.Conn) (host string, port int, err error) {
	t.Helper()
	var atyp [1]byte
	if err = readFullOrDead(t, c, atyp[:]); err != nil {
		return "", 0, err
	}
	switch atyp[0] {
	case socks5TestAtypIPv4:
		var raw [6]byte
		if err = readFullOrDead(t, c, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:4]).String(), int(binary.BigEndian.Uint16(raw[4:])), nil
	case socks5TestAtypIPv6:
		var raw [18]byte
		if err = readFullOrDead(t, c, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:16]).String(), int(binary.BigEndian.Uint16(raw[16:])), nil
	case socks5TestAtypDomain:
		var l [1]byte
		if err = readFullOrDead(t, c, l[:]); err != nil {
			return "", 0, err
		}
		raw := make([]byte, int(l[0])+2)
		if err = readFullOrDead(t, c, raw); err != nil {
			return "", 0, err
		}
		return string(raw[:l[0]]), int(binary.BigEndian.Uint16(raw[l[0]:])), nil
	default:
		return "", 0, io.ErrUnexpectedEOF
	}
}

// writeSocks5TestReply writes VER REP RSV BND.ADDR BND.PORT.
func writeSocks5TestReply(t *testing.T, c net.Conn, rep byte, bndIP net.IP, bndPort int) error {
	t.Helper()
	frame := []byte{socks5TestVer, rep, 0, socks5TestAtypIPv4, 0, 0, 0, 0, 0, 0}
	if rep == socks5TestRepSuccess {
		ip := bndIP.To4()
		if ip == nil {
			ip = bndIP.To16()
			frame[3] = socks5TestAtypIPv6
		}
		copy(frame[4:], ip)
		binary.BigEndian.PutUint16(frame[len(frame)-2:], uint16(bndPort))
	}
	return writeFullOrDead(t, c, frame)
}

// decodeSocks5UdpDatagram splits one RFC 1928 section 7 datagram
// (RSV FRAG ATYP DST.ADDR DST.PORT DATA) into its target and payload.
func decodeSocks5UdpDatagram(b []byte) (dst net.Addr, payload []byte, ok bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return nil, nil, false // RSV/FRAG must be zero: we never fragment
	}
	rest := b[3:]
	switch rest[0] {
	case socks5TestAtypIPv4:
		if len(rest) < 7 {
			return nil, nil, false
		}
		ip := append(net.IP(nil), rest[1:5]...)
		return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(rest[5:7]))}, rest[7:], true
	case socks5TestAtypIPv6:
		if len(rest) < 19 {
			return nil, nil, false
		}
		ip := append(net.IP(nil), rest[1:17]...)
		return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(rest[17:19]))}, rest[19:], true
	case socks5TestAtypDomain:
		if len(rest) < 2 {
			return nil, nil, false
		}
		l := int(rest[1])
		if len(rest) < 2+l+2 {
			return nil, nil, false
		}
		host := net.JoinHostPort(string(rest[2:2+l]), strconv.Itoa(int(binary.BigEndian.Uint16(rest[2+l:]))))
		ua, err := net.ResolveUDPAddr("udp", host)
		if err != nil {
			return nil, nil, false
		}
		return ua, rest[2+l+2:], true
	default:
		return nil, nil, false
	}
}

// encodeSocks5UdpDatagram frames a relayed datagram with its source address
// the same RFC 1928 section 7 layout.
func encodeSocks5UdpDatagram(from net.Addr, payload []byte) ([]byte, bool) {
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		return nil, false
	}
	ip := ua.IP.To4()
	atyp := socks5TestAtypIPv4
	if ip == nil {
		ip = ua.IP.To16()
		atyp = socks5TestAtypIPv6
		if ip == nil {
			return nil, false
		}
	}
	frame := make([]byte, 0, 4+len(ip)+2+len(payload))
	frame = append(frame, 0, 0, 0, atyp)
	frame = append(frame, ip...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(ua.Port))
	frame = append(frame, port[:]...)
	frame = append(frame, payload...)
	return frame, true
}

// serveSocks5Conn handles one accepted control connection: method negotiation
// (0x00 or 0x02), optional RFC 1929 username/password, then CONNECT relay to
// a real loopback target with half-close propagation, or UDP ASSOCIATE relay.
func (srv *socks5TestServer) serveSocks5Conn(t *testing.T, downstream net.Conn) {
	t.Helper()
	defer func() { _ = downstream.Close() }()

	// RFC 1928 section 3: method negotiation.
	var hdr [2]byte // VER NMETHODS
	if err := readFullOrDead(t, downstream, hdr[:]); err != nil {
		return
	}
	if hdr[0] != socks5TestVer || hdr[1] == 0 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if err := readFullOrDead(t, downstream, methods); err != nil {
		return
	}
	method := socks5TestAuthNoAcceptable
	if srv.opts.requireAuth {
		if bytes.IndexByte(methods, socks5TestAuthPassword) >= 0 {
			method = socks5TestAuthPassword
		}
	} else if bytes.IndexByte(methods, socks5TestAuthNone) >= 0 {
		method = socks5TestAuthNone
	}
	srv.recordMethod(method)
	if err := writeFullOrDead(t, downstream, []byte{socks5TestVer, method}); err != nil {
		return
	}
	if method == socks5TestAuthNoAcceptable {
		return // real servers close after offering nothing acceptable
	}

	if method == socks5TestAuthPassword {
		// RFC 1929 section 2: VER ULEN UNAME PLEN PASSWD.
		var verAndUlen [2]byte
		if err := readFullOrDead(t, downstream, verAndUlen[:]); err != nil {
			return
		}
		if verAndUlen[0] != socks5TestPasswordSubNegotiation {
			return
		}
		uname := make([]byte, int(verAndUlen[1]))
		if err := readFullOrDead(t, downstream, uname); err != nil {
			return
		}
		var plen [1]byte
		if err := readFullOrDead(t, downstream, plen[:]); err != nil {
			return
		}
		passwd := make([]byte, int(plen[0]))
		if err := readFullOrDead(t, downstream, passwd); err != nil {
			return
		}
		srv.recordAuth(string(uname), string(passwd))
		if string(uname) != srv.opts.username || string(passwd) != srv.opts.password {
			_ = writeFullOrDead(t, downstream, []byte{socks5TestPasswordSubNegotiation, 1}) // status: failure
			return
		}
		if err := writeFullOrDead(t, downstream, []byte{socks5TestPasswordSubNegotiation, 0}); err != nil {
			return
		}
	}

	// RFC 1928 section 4: request.
	var req [3]byte // VER CMD RSV
	if err := readFullOrDead(t, downstream, req[:]); err != nil {
		return
	}
	if req[0] != socks5TestVer {
		return
	}
	host, port, err := readSocks5TestAddress(t, downstream)
	if err != nil {
		return
	}
	destination := net.JoinHostPort(host, strconv.Itoa(port))

	switch req[1] {
	case socks5TestCmdConnect:
		if srv.opts.connectReply != socks5TestRepSuccess {
			// REP != 0 with a zero BND: the client must fail the dial.
			_ = writeSocks5TestReply(t, downstream, srv.opts.connectReply, net.IPv4zero, 0)
			return
		}
		target, err := net.DialTimeout("tcp", destination, 10*time.Second)
		if err != nil {
			_ = writeSocks5TestReply(t, downstream, socks5TestRepGeneralFailure, net.IPv4zero, 0)
			return
		}
		defer func() { _ = target.Close() }()
		bnd, ok := srv.ln.Addr().(*net.TCPAddr)
		if !ok {
			return
		}
		if err := writeSocks5TestReply(t, downstream, socks5TestRepSuccess, bnd.IP, bnd.Port); err != nil {
			return
		}
		// Relay; drop the handshake deadlines so the relay is not bounded by
		// them, and propagate the client's FIN to the echo target.
		_ = downstream.SetDeadline(time.Time{})
		go func() {
			_, copyErr := io.Copy(target, downstream)
			if copyErr == nil {
				srv.markDownstreamEOF() // a clean client half-close reached us
			}
			if tcp, ok := target.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		}()
		_, _ = io.Copy(downstream, target)
	case socks5TestCmdUDPAssociate:
		srv.serveUdpAssociate(t, downstream)
	}
}

// serveUdpAssociate replies with a real UDP relay endpoint and relays
// framed datagrams between the client endpoint and the echo targets it
// addresses (RFC 1928 section 7).

// socks5EgressPortSeq hands out distinct loopback ports for per-association
// egress sockets. The ports are explicit rather than ephemeral so that a fresh
// association provably presents a fresh forwarding identity: with the kernel's
// ephemeral allocator a just-closed port could be handed straight back, which
// would make the far end's reaped-mapping state ambiguous instead of absent.
var socks5EgressPortSeq atomic.Int32

func bindSocks5EgressSocket(t *testing.T) net.PacketConn {
	t.Helper()
	for i := 0; i < 500; i++ {
		port := 35000 + int(socks5EgressPortSeq.Add(1))
		pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			return pc
		}
	}
	t.Fatal("no free loopback port for the socks5 egress socket")
	return nil
}

// serveUdpAssociate implements RFC 1928 UDP ASSOCIATE with one egress socket per
// association. The relay socket only faces the client; datagrams to the target
// leave from the association's own egress socket, so the target observes a
// per-association source port — the forwarding identity dae's reply-drought
// rebuild has to renew.
// startSocks5ServerWithUDPRedirect starts the in-test server with a UDP
// destination rewrite table.
func startSocks5ServerWithUDPRedirect(t *testing.T, opts socks5ServerOptions, redirect map[netip.AddrPort]netip.AddrPort) *socks5TestServer {
	t.Helper()
	srv := startSocks5Server(t, opts)
	srv.udpRedirect = redirect
	return srv
}

func (srv *socks5TestServer) serveUdpAssociate(t *testing.T, control net.Conn) {
	t.Helper()
	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer func() { _ = relay.Close() }()
	egress := bindSocks5EgressSocket(t)
	defer func() { _ = egress.Close() }()
	relayAddr, ok := relay.LocalAddr().(*net.UDPAddr)
	if !ok {
		return
	}
	if err := writeSocks5TestReply(t, control, socks5TestRepSuccess, relayAddr.IP, relayAddr.Port); err != nil {
		return
	}
	// The control connection now only idles until the association ends, so
	// drop the handshake deadlines.
	_ = control.SetDeadline(time.Time{})

	// Tear the association down when the control connection dies.
	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := control.Read(buf); err != nil {
				_ = relay.Close()
				_ = egress.Close()
				return
			}
		}
	}()

	var clientAddr atomic.Value  // net.Addr
	var requestedAt atomic.Value // netip.AddrPort
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := relay.ReadFrom(buf)
			if err != nil {
				return
			}
			if clientAddr.Load() == nil {
				clientAddr.Store(from)
			}
			dst, payload, ok := decodeSocks5UdpDatagram(buf[:n])
			if !ok {
				return // malformed frame: kill the association like a real server
			}
			udpDst, ok := dst.(*net.UDPAddr)
			if !ok {
				return
			}
			requested := udpDst.AddrPort()
			if wanted, ok := srv.udpRedirect[requested]; ok {
				requestedAt.Store(requested)
				dst = net.UDPAddrFromAddrPort(wanted)
			}
			if _, err := egress.WriteTo(payload, dst); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, from, err := egress.ReadFrom(buf)
		if err != nil {
			return
		}
		addr, _ := clientAddr.Load().(net.Addr)
		if addr == nil {
			continue // the client has not spoken yet
		}
		// Report the address the client asked for, not the internal forward
		// target, whenever a redirect is in effect.
		reported := from
		if requested, ok := requestedAt.Load().(netip.AddrPort); ok && len(srv.udpRedirect) > 0 {
			reported = net.UDPAddrFromAddrPort(requested)
		}
		frame, ok := encodeSocks5UdpDatagram(reported, buf[:n])
		if !ok {
			return
		}
		if _, err := relay.WriteTo(frame, addr); err != nil {
			return
		}
	}
}
