package control

import (
	"encoding/binary"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// Dae event types mirror enum dae_event_type in control/kern/tproxy.c.
const (
	daeEventBlocked = iota
	daeEventUdpConnOverflow
	daeEventTcpConnOverflow
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
			}
		}
	}()
}
