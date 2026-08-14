package control

import (
	"encoding/binary"
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

// daeEvent mirrors struct dae_event in control/kern/tproxy.c (72 bytes,
// little-endian). Parsed manually to avoid struct-padding surprises.
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

func parseDaeEvent(b []byte) (e daeEvent) {
	if len(b) < 72 {
		return e
	}
	e.Timestamp = binary.LittleEndian.Uint64(b[0:8])
	e.Type = binary.LittleEndian.Uint32(b[8:12])
	e.Pid = binary.LittleEndian.Uint32(b[12:16])
	copy(e.Pname[:], b[16:32])
	e.Outbound = b[32]
	e.L4proto = b[33]
	for i := 0; i < 4; i++ {
		e.Sip[i] = binary.LittleEndian.Uint32(b[36+4*i : 40+4*i])
		e.Dip[i] = binary.LittleEndian.Uint32(b[52+4*i : 56+4*i])
	}
	e.Sport = binary.LittleEndian.Uint16(b[68:70])
	e.Dport = binary.LittleEndian.Uint16(b[70:72])
	return e
}

// startEventRingbufReader consumes kernel ringbuf events and forwards
// conn-state overflow events to the conn state janitor, making the janitor
// event-driven instead of purely polling. The reader blocks in ReadInto; it
// is woken by Close (from stopConnStateJanitor or on its own exit path).
//
// The reader re-opens on error so a datapath reload (which replaces the
// ringbuf map) does not strand it on a dead map. When the eBPF objects are
// unavailable (stub builds) it simply parks: the janitor's polling backoff
// remains the fallback.
func (c *ControlPlane) startEventRingbufReader(overflowEvent chan<- struct{}) {
	if c == nil {
		return
	}
	go func() {
		var reader *ringbuf.Reader
		defer func() {
			if reader != nil {
				_ = reader.Close()
			}
		}()
		for {
			select {
			case <-c.connStateJanitorStop:
				return
			case <-c.ctx.Done():
				return
			default:
			}
			if reader == nil {
				bpf := c.currentBpf()
				if bpf == nil || bpf.EventRingbuf == nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				r, err := ringbuf.NewReader(bpf.EventRingbuf)
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				reader = r
				c.connEventReader.Store(r)
			}
			record := ringbuf.Record{}
			if err := reader.ReadInto(&record); err != nil {
				// Datapath replaced (reload) or closed: re-open on the
				// current map, or park until one exists.
				_ = reader.Close()
				reader = nil
				time.Sleep(100 * time.Millisecond)
				continue
			}
			ev := parseDaeEvent(record.RawSample)
			switch ev.Type {
			case daeEventUdpConnOverflow, daeEventTcpConnOverflow:
				select {
				case overflowEvent <- struct{}{}:
				default: // janitor busy; its own polling will catch up
				}
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
				c.handleBlockedAliveEvent(&ev)
			}
		}
	}()
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
