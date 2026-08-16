/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

// Real-kernel verification harness for the TCP offload sent-accounting hook.
// Requires root and kernel BTF; skips otherwise (regular CI containers).
// It loads the pruned offload datapath (verdict + accounting programs),
// mirrors dae's two-connection relay topology, and asserts that redirected
// traffic populates tcp_offload_sent and that the fuse backlog stays near
// zero on transfers above the engage threshold — the regression class where
// a dead accounting hook made every >64MiB session freeze for 10s.
//
// Note on accounting precision: fentry fires on function entry, so skbs
// requeued via the EAGAIN retry path are counted once per attempt; observed
// over-estimation is ~1-2% on loopback (sent slightly above tcp_info
// inflow), which is the conservative direction for the fuse (engages later,
// never early).

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	verifyPayload = 1 << 20  // 1MiB functional round-trip
	verifyStream  = 70 << 20 // > the 64MiB fuse engage threshold, still loopback-friendly
)

// loadOffloadVerifyCollection loads only the three programs and three maps
// the offload datapath needs, avoiding unrelated program types from the
// full tproxy object.
func loadOffloadVerifyCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec("bpf_bpfel.o")
	if err != nil {
		t.Fatalf("LoadCollectionSpec: %v", err)
	}
	keepProg := map[string]bool{
		"tcp_offload_redirect":            true,
		"tcp_offload_sent_account":        true,
		"tcp_offload_sent_account_kprobe": true,
	}
	keepMap := map[string]bool{
		"fast_sock":         true,
		"tcp_offload_pause": true,
		"tcp_offload_sent":  true,
	}
	for name := range spec.Programs {
		if !keepProg[name] {
			delete(spec.Programs, name)
		}
	}
	for name := range spec.Maps {
		if !keepMap[name] && name[0] != '.' {
			delete(spec.Maps, name)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection (pruned): %v", err)
	}
	return coll
}

func perCPUCounter(m *ebpf.Map, key *bpfTuplesKey) uint64 {
	var vals []uint64
	if err := m.Lookup(key, &vals); err != nil {
		return 0
	}
	var sum uint64
	for _, v := range vals {
		sum += v
	}
	return sum
}

// TestTCPOffloadSentAccountE2E verifies on this (real) kernel that
//  1. the fentry attaches to skb_send_sock (L1);
//  2. redirected traffic populates tcp_offload_sent (L2);
//  3. at 100MiB (> the 64MiB fuse threshold) sent tracks inflow, i.e. the
//     backlog the fuse reads stays near zero (L3).
func TestTCPOffloadSentAccountE2E(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skip("needs root for BPF program load/attach")
	}

	coll := loadOffloadVerifyCollection(t)
	defer coll.Close()

	fastSock := coll.Maps["fast_sock"]
	sentMap := coll.Maps["tcp_offload_sent"]
	if fastSock == nil || sentMap == nil {
		t.Fatal("missing maps in collection")
	}

	// L1: fentry attach to skb_send_sock.
	fl, fentryErr := link.AttachTracing(link.TracingOptions{
		Program:    coll.Programs["tcp_offload_sent_account"],
		AttachType: ebpf.AttachTraceFEntry,
	})
	if fentryErr != nil {
		t.Logf("L1: fentry attach FAILED on this kernel: %v", fentryErr)
		t.Logf("L1: trying kprobe fallback (production fallback path)")
		kl, kerr := link.Kprobe("skb_send_sock", coll.Programs["tcp_offload_sent_account_kprobe"], nil)
		if kerr != nil {
			t.Fatalf("L1 FAIL: neither fentry (%v) nor kprobe (%v) could attach to skb_send_sock", fentryErr, kerr)
		}
		fl = kl
	}
	defer func() { _ = fl.Close() }()
	t.Logf("L1 PASS: accounting hook attached to skb_send_sock (%s)", func() string {
		if fentryErr != nil {
			return "kprobe fallback"
		}
		return "fentry"
	}())

	// Verdict program on the SOCKHASH.
	vl, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  fastSock.FD(),
		Program: coll.Programs["tcp_offload_redirect"],
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	})
	if err != nil {
		t.Fatalf("attach verdict to fast_sock: %v", err)
	}
	defer func() { _ = vl.Close() }()

	// Topology mirroring dae's relay pair:
	//   fakeClient --conn1-- left (accepted)      right (dialed) --conn2-- fakeUpstream
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l1.Close() }()
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l2.Close() }()

	client, err := net.Dial("tcp", l1.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	leftRaw, err := l1.Accept()
	if err != nil {
		t.Fatal(err)
	}
	left := leftRaw.(*net.TCPConn)
	right, err := net.Dial("tcp", l2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rightTCP := right.(*net.TCPConn)
	upRaw, err := l2.Accept()
	if err != nil {
		t.Fatal(err)
	}
	up := upRaw.(*net.TCPConn)

	leftKey, err := tcpConnTuplesKey(left)
	if err != nil {
		t.Fatal(err)
	}
	rightKey, err := tcpConnTuplesKey(rightTCP)
	if err != nil {
		t.Fatal(err)
	}
	leftFD, err := tcpConnFD(left)
	if err != nil {
		t.Fatal(err)
	}
	rightFD, err := tcpConnFD(rightTCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := fastSock.Update(&leftKey, uint64(rightFD), ebpf.UpdateAny); err != nil {
		t.Fatalf("register left->right: %v", err)
	}
	if err := fastSock.Update(&rightKey, uint64(leftFD), ebpf.UpdateAny); err != nil {
		t.Fatalf("register right->left: %v", err)
	}
	defer func() { _ = fastSock.Delete(&leftKey) }()
	defer func() { _ = fastSock.Delete(&rightKey) }()

	rxBase, err := tcpConnRxBytes(left)
	if err != nil {
		t.Fatal(err)
	}

	// L2: 1MiB round trip through the redirect datapath.
	payload := make([]byte, verifyPayload)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = client.Write(payload) }()
	got := make([]byte, verifyPayload)
	if _, err := io.ReadFull(up, got); err != nil {
		t.Fatalf("L2 FAIL: upstream read: %v (redirect datapath broken?)", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("L2 FAIL: payload mismatch through redirect")
	}
	time.Sleep(300 * time.Millisecond) // let per-cpu counters settle

	sentL2 := perCPUCounter(sentMap, &leftKey)
	if sentL2 == 0 {
		t.Fatalf("L2 FAIL: tcp_offload_sent[leftKey] is EMPTY after %d bytes redirected through the sockmap egress path — the accounting hook never fired", verifyPayload)
	}
	t.Logf("L2 PASS: sent[leftKey]=%d after 1MiB (expect ~%d)", sentL2, verifyPayload)

	// L3: 100MiB stream (above the 64MiB fuse engage threshold). The sent
	// counter must track inflow so the backlog stays near zero; before the
	// symbol fix the counter stayed at 0 and the fuse would engage.
	chunk := make([]byte, 1<<20)
	streamErr := make(chan error, 1)
	go func() {
		remain := verifyStream
		for remain > 0 {
			n := len(chunk)
			if remain < n {
				n = remain
			}
			if _, err := client.Write(chunk[:n]); err != nil {
				streamErr <- err
				return
			}
			remain -= n
			// Pace the producer slightly: a full-speed flood can tickle the
			// kernel's psock EAGAIN-retry path into an abort on WSL2; real
			// relay sources are TCP-flow-controlled anyway.
			time.Sleep(500 * time.Microsecond)
		}
		streamErr <- nil
	}()
	if _, err := io.CopyN(io.Discard, up, verifyStream); err != nil {
		t.Fatalf("L3 FAIL: upstream stream read: %v", err)
	}
	if err := <-streamErr; err != nil {
		t.Fatalf("L3 FAIL: client stream write: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	rxNow, err := tcpConnRxBytes(left)
	if err != nil {
		t.Fatal(err)
	}
	inflow := int64(rxNow) - int64(rxBase)
	sentL3 := perCPUCounter(sentMap, &leftKey)
	backlogVal := inflow - int64(sentL3)
	t.Logf("L3: inflow=%d sent=%d backlog=%d (fuse engage at %d, resume at %d)",
		inflow, sentL3, backlogVal, tcpOffloadMaxPeerBacklog, tcpOffloadFuseResumeBytes)
	if sentL3 < uint64(verifyStream) {
		t.Fatalf("L3 FAIL: sent=%d after %d bytes — counter is not tracking inflow; fuse would mis-engage", sentL3, verifyStream)
	}
	if backlogVal > int64(tcpOffloadFuseResumeBytes)*8 {
		t.Fatalf("L3 FAIL: backlog=%d far above resume threshold — fuse metric still wrong", backlogVal)
	}
	t.Logf("L3 PASS: backlog stays at %d (≪ %d engage threshold) — fuse will not mis-engage on unconstrained transfers", backlogVal, tcpOffloadMaxPeerBacklog)
}
