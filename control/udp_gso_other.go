//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net"
	"syscall"
)

var errGSONotSupported = errors.New("udp gso/gro not supported on non-linux platforms")

func EnableUDPGRO(conn *net.UDPConn) error {
	return errGSONotSupported
}

func ProbeUDPGSO(conn *net.UDPConn) bool {
	return false
}

func BuildUDPGSOControlMsg(segmentSize uint16) []byte {
	return nil
}

func WriteUDPGSO(rawConn syscall.RawConn, payload []byte, segmentSize uint16, to any) (int, error) {
	return 0, errGSONotSupported
}

func ParseUDPGRO(oob []byte) (int, bool) {
	return 0, false
}

func SplitUDPGROPayload(payload []byte, segmentSize int) [][]byte {
	return [][]byte{payload}
}
