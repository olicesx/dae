//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <daeuniverse/dae>
 */

package control

import (
	stderrors "errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSplicePipeToSocketWrapsErrno locks the error shape of the raw splice
// loop: a terminal splice(2) failure must carry the operation name
// ("splice: broken pipe") like the standard library's splice path does, and
// must stay identity-comparable to the bare errno so errors.Is-based
// classifiers keep working.
func TestSplicePipeToSocketWrapsErrno(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socketpair unavailable: %v", err)
	}
	// Dropping the peer makes writes on the kept end fail with EPIPE.
	_ = unix.Close(fds[1])

	file := os.NewFile(uintptr(fds[0]), "splice-errno-test")
	defer func() { _ = file.Close() }()
	conn, err := net.FileConn(file)
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	defer func() { _ = conn.Close() }()
	rawConn, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	pipe, err := newRelaySplicePipe()
	if err != nil {
		t.Fatalf("newRelaySplicePipe: %v", err)
	}
	defer pipe.close()
	// One byte in the pipe so splice has data to move instead of EAGAIN.
	if _, err := unix.Write(pipe.writeFD, []byte{0}); err != nil {
		t.Fatalf("pipe write: %v", err)
	}

	_, err = splicePipeToSocket(rawConn, pipe.readFD, 1)
	if err == nil {
		t.Fatal("expected EPIPE splicing into a socket whose peer closed")
	}
	if !stderrors.Is(err, syscall.EPIPE) {
		t.Fatalf("error %v must stay identity-comparable to syscall.EPIPE", err)
	}
	if !strings.Contains(err.Error(), "splice") {
		t.Fatalf("error %q must name the failing operation", err.Error())
	}
}
