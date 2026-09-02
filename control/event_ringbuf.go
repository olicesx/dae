package control

import (
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// Dae event types mirror enum dae_event_type in control/kern/tproxy.c.
const (
	daeEventBlocked = iota
	daeEventUdpConnOverflow
	daeEventTcpConnOverflow
	daeEventBlockedAlive
)

// daeEvent mirrors struct dae_event in control/kern/tproxy.c. The kernel writes
// native-endian scalars into the 72-byte ringbuf record.
type daeEvent struct {
	Timestamp uint64
	Type      uint32
	Pid       uint32
	Pname     [16]byte
	Outbound  uint8
	L4proto   uint8
	Sip       [4]uint32
	Dip       [4]uint32
	Sport     uint16
	Dport     uint16
}

func parseDaeEvent(b []byte) daeEvent {
	return parseDaeEventWithABI(nativeBpfABI, b)
}

func parseDaeEventWithABI(abi bpfHostABI, b []byte) (e daeEvent) {
	if len(b) < 72 {
		return e
	}
	e.Timestamp = abi.uint64(b[0:8])
	e.Type = abi.uint32(b[8:12])
	e.Pid = abi.uint32(b[12:16])
	copy(e.Pname[:], b[16:32])
	e.Outbound = b[32]
	e.L4proto = b[33]
	for i := 0; i < 4; i++ {
		e.Sip[i] = abi.uint32(b[36+4*i : 40+4*i])
		e.Dip[i] = abi.uint32(b[52+4*i : 56+4*i])
	}
	e.Sport = abi.uint16(b[68:70])
	e.Dport = abi.uint16(b[70:72])
	return e
}

// startEventRingbufReader consumes kernel ringbuf events and forwards
// conn-state overflow events to the conn state janitor, making the janitor
// event-driven instead of purely polling. The reader blocks in ReadInto; it
// is woken by Close when the owning BPF runtime stops.
//
// The reader re-opens the same runtime-owned map after transient errors. A
// fresh BPF object set gets a separate runtime; shared reloads keep this reader
// alive. Stub builds simply park and retain periodic cleanup as the fallback.
func (r *bpfMaintenanceRuntime) readEvents() {
	var reader *ringbuf.Reader
	defer func() {
		if reader != nil {
			_ = reader.Close()
		}
	}()
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		if reader == nil {
			if r.bpf == nil || r.bpf.EventRingbuf == nil {
				select {
				case <-r.stop:
					return
				case <-time.After(100 * time.Millisecond):
					continue
				}
			}
			opened, err := ringbuf.NewReader(r.bpf.EventRingbuf)
			if err != nil {
				select {
				case <-r.stop:
					return
				case <-time.After(100 * time.Millisecond):
					continue
				}
			}
			reader = opened
			r.reader.Store(opened)
			select {
			case <-r.stop:
				_ = reader.Close()
				r.reader.Store(nil)
				reader = nil
				return
			default:
			}
		}
		record := ringbuf.Record{}
		if err := reader.ReadInto(&record); err != nil {
			_ = reader.Close()
			reader = nil
			r.reader.Store(nil)
			continue
		}
		target := r.active.Load()
		if target == nil {
			continue
		}
		ev := parseDaeEvent(record.RawSample)
		switch ev.Type {
		case daeEventUdpConnOverflow, daeEventTcpConnOverflow:
			r.requestOverflow(target)
		case daeEventBlockedAlive:
			// Kernel blocked a packet because the selected outbound is
			// not alive (wan_outbound_is_alive == false). Userspace never
			// sees this flow (it is dropped before tproxy), so the normal
			// dial-error path can't trigger resuscitation here. Trigger a
			// group-level resuscitation probe so recovery does not wait
			// for the next periodic health check. Resuscitate is
			// rate-limited per group; the kernel additionally rate-limits
			// event emission per outbound (1/s), so this cannot storm the
			// probe workers.
			target.handleBlockedAliveEvent(&ev)
		}
	}
}

// handleBlockedAliveEvent reacts to a kernel DAE_EVENT_BLOCKED_ALIVE by
// probing the affected outbound group for the blocked protocol family.
func (c *ControlPlane) handleBlockedAliveEvent(ev *daeEvent) {
	if c == nil || c.core == nil {
		return
	}
	idx := int(ev.Outbound)
	state := c.controlPlaneGenerationState
	if idx >= len(state.outbounds) {
		return
	}
	group := state.outbounds[idx]
	if group == nil {
		return
	}
	networkType := &dialer.NetworkType{}
	switch ev.L4proto {
	case unix.IPPROTO_TCP:
		networkType.L4Proto = consts.L4ProtoStr_TCP
	case unix.IPPROTO_UDP:
		networkType.L4Proto = consts.L4ProtoStr_UDP
	default:
		// Kernel only emits BLOCKED_ALIVE for TCP/UDP; unknown values are
		// ignored rather than defaulting to a probe of the wrong family.
		return
	}
	networkType.IpVersion = consts.IpVersionStr_4 // probe both; Resuscitate fans out
	group.Resuscitate(networkType)
}
