/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

// TproxyTCPMaxSeg defines the maximum segment size clamped on the Tproxy stream listener.
// Clamping prevents oversize packets when proxied traffic is later encapsulated in tunnel protocols.
// Setting TproxyTCPMaxSeg <= 0 disables MSS clamping on the listener.
// Note: On Linux TCP connections with timestamp options (12 bytes), setting TCP_MAXSEG to 1380
// yields an effective payload MSS of ~1368 bytes in data segments.
var TproxyTCPMaxSeg = 1380

func SoMarkControl(c syscall.RawConn, mark int) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, fwmarkIoctl, mark)
		if err != nil {
			sockOptErr = fmt.Errorf("error setting SO_MARK socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

func TproxyControl(c syscall.RawConn) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		// - https://www.kernel.org/doc/Documentation/networking/tproxy.txt
		if err := setTransparentSocketOptions(int(fd)); err != nil {
			sockOptErr = err
			return
		}

		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting SO_REUSEADDR socket option: %w", err)
			return
		}

		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting SO_REUSEPORT socket option: %w", err)
			return
		}

		e4 := unix.SetsockoptInt(int(fd), syscall.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		e6 := unix.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		if e4 != nil && e6 != nil {
			// Both IPv4 and IPv6 original destination retrieval failed.
			// Surface e4 as the primary error (IPv4 is the more common path).
			sockOptErr = fmt.Errorf("error setting IP_RECVORIGDSTADDR socket option: %w", e4)
			return
		}

		// Check socket type: apply TCP-specific options only on stream sockets.
		// RFC 7413 note: We explicitly do NOT set TCP_FASTOPEN on this transparent proxy listener.
		// Tproxy listener receives redirected SYNs with cookies minted for the real destination,
		// which would fail validation and risk unconsented duplicate delivery of non-idempotent data.
		if sockType, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE); err == nil && sockType == unix.SOCK_STREAM {
			if TproxyTCPMaxSeg > 0 {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, TproxyTCPMaxSeg)
			}
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

func setTransparentSocketOptions(fd int) error {
	e4 := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1)
	e6 := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1)
	if e4 != nil && e6 != nil {
		return fmt.Errorf("error setting transparent socket options: ipv4=%v, ipv6=%v", e4, e6)
	}
	return nil
}

func TransparentControl(c syscall.RawConn) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		if err := setTransparentSocketOptions(int(fd)); err != nil {
			sockOptErr = err
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting SO_REUSEADDR socket option: %w", err)
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting SO_REUSEPORT socket option: %w", err)
			return
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}
