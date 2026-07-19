/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/daedns"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type retireTestTransport struct {
	peer       net.Conn
	retired    atomic.Bool
	closeCalls atomic.Int32
}

func (d *retireTestTransport) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	conn, peer := net.Pipe()
	d.peer = peer
	return conn, nil
}

func (d *retireTestTransport) RetireForEstablishedFlows() {
	d.retired.Store(true)
}

func (d *retireTestTransport) Close() error {
	d.closeCalls.Add(1)
	if d.peer != nil {
		return d.peer.Close()
	}
	return nil
}

func TestRetireForEstablishedFlowsDropsDNSMetadataAndKeepsConnection(t *testing.T) {
	log := logrus.New()
	option := &GlobalOption{
		Log:            log,
		DaeDNS:         &daedns.Router{},
		CheckInterval:  time.Second,
		CheckTolerance: time.Second,
	}
	transport := &retireTestTransport{}
	d := NewDialer(
		transport,
		option,
		InstanceOption{DisableCheck: true},
		&Property{},
	)
	d.metadataRetirer = transport

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	d.RetireForEstablishedFlows()
	if option.DaeDNS != nil {
		t.Fatal("retired dialer retained GlobalOption.DaeDNS")
	}
	if !transport.retired.Load() {
		t.Fatal("retired dialer did not detach protocol-chain metadata")
	}
	if got := transport.closeCalls.Load(); got != 0 {
		t.Fatalf("transport close calls during retirement = %d, want 0", got)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := conn.Write([]byte("still-live"))
		writeDone <- writeErr
	}()
	buf := make([]byte, len("still-live"))
	if _, err = transport.peer.Read(buf); err != nil {
		t.Fatalf("active transport read after retirement error = %v", err)
	}
	if err = <-writeDone; err != nil {
		t.Fatalf("active connection write after retirement error = %v", err)
	}
	if got := string(buf); got != "still-live" {
		t.Fatalf("active transport payload = %q, want %q", got, "still-live")
	}

	if err = d.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := transport.closeCalls.Load(); got != 1 {
		t.Fatalf("transport close calls after final release = %d, want 1", got)
	}
}
