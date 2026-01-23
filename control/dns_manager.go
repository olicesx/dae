package control

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

const (
	dnsRetryInterval = 1 * time.Second
	dnsRetryCount    = 2
)

type LeveledError interface {
	error
	Level() log.Level
}

type leveledError struct {
	err   error
	level log.Level
}

func (e *leveledError) Error() string {
	return e.err.Error()
}

func (e *leveledError) Unwrap() error {
	return e.err
}

func (e *leveledError) Level() log.Level {
	return e.level
}

func wrapLevel(err error, level log.Level) error {
	if err == nil {
		return nil
	}
	return &leveledError{err: err, level: level}
}

func AsInfo(err error) error  { return wrapLevel(err, log.InfoLevel) }
func AsWarn(err error) error  { return wrapLevel(err, log.WarnLevel) }
func AsError(err error) error { return wrapLevel(err, log.ErrorLevel) }
func AsDebug(err error) error { return wrapLevel(err, log.DebugLevel) }
func AsTrace(err error) error { return wrapLevel(err, log.TraceLevel) }

type DnsManager struct {
	conn    net.Conn
	recvMap sync.Map // map[uint32]chan *dnsmessage.Msg
	ctx     context.Context
	cancel  context.CancelFunc

	stream bool
	dialer string
}

func NewDnsManager(conn net.Conn, stream bool, dialer string) *DnsManager {
	ctx, cancel := context.WithCancel(context.TODO())
	m := &DnsManager{
		conn:   conn,
		ctx:    ctx,
		cancel: cancel,
		stream: stream,
		dialer: dialer,
	}
	go m.run()
	return m
}

func (m *DnsManager) run() {
	buf := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(buf)
	for {
		var data []byte
		var err error
		if data, err = m.read(buf); err != nil {
			var le LeveledError
			if errors.As(err, &le) {
				log.WithError(err).Logf(le.Level(), "DnsManager closed, dialer: %v", m.dialer)
			}
			m.Close()
			return
		}
		m.feed(data)
	}
}

func (m *DnsManager) read(buf []byte) (data []byte, err error) {
	if m.stream {
		msgLenBuf := buf[:2]
		// Read two byte length.
		if _, err = io.ReadFull(m.conn, msgLenBuf); err != nil {
			return data, AsDebug(oops.Wrapf(err, "failed to read tcp DNS resp payload length"))
		}
		msgLen := int(binary.BigEndian.Uint16(msgLenBuf))
		if msgLen > len(buf) {
			return data, AsWarn(oops.Wrapf(err, "tcp dns msg len too large: %d > %d", msgLen, len(buf)))
		}
		data = buf[:msgLen]
		if _, err = io.ReadFull(m.conn, data); err != nil {
			return data, AsDebug(oops.Wrapf(err, "failed to read tcp DNS resp payload"))
		}
	} else {
		var n int
		if n, err = m.conn.Read(buf); err != nil {
			return data, AsError(oops.Wrapf(err, "failed to read udp DNS resp payload"))
		}
		data = buf[:n]
	}
	return data, nil
}

func (m *DnsManager) feed(data []byte) {
	// Create new DNS message directly (no pool for simplicity and safety)
	msg := &dnsmessage.Msg{}

	err := msg.Unpack(data)
	if err != nil {
		log.Warnf("Failed to unpack dns resp, stream: %v, err: %v, data: %v", m.stream, err, data)
		return
	}
	conn, ok := m.recvMap.Load(msg.Id)
	if !ok {
		log.Debugf("Unknown dns resp msg, stream: %v, id: %v", m.stream, msg.Id)
		return
	}

	select {
	case conn.(chan *dnsmessage.Msg) <- msg:
		// OK - message is now owned by the receiver
		return
	default:
		log.Debugf("Drop dns resp msg, stream: %v, id: %v", m.stream, msg.Id)
		return
	}
}

func (m *DnsManager) Close() error {
	m.cancel()
	return m.conn.Close()
}

func (m *DnsManager) IsClosed() bool {
	return m.ctx.Err() != nil
}

func (m *DnsManager) Resolve(ctx context.Context, msg *dnsmessage.Msg) error {
	origMsgId := msg.Id
	msg.Id = uint16(fastrand.Intn(math.MaxUint16))
	defer func() { msg.Id = origMsgId }()
	buf := pool.GetBuffer(1024)
	defer pool.PutBuffer(buf)
	var data []byte
	var err error
	if m.stream {
		if data, err = msg.PackBuffer(buf[2:]); err == nil {
			dataLen := uint16(len(data))
			binary.BigEndian.PutUint16(buf, dataLen)
			data = buf[:dataLen+2]
		}
	} else {
		data, err = msg.PackBuffer(buf)
	}
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}

	recvCh := make(chan *dnsmessage.Msg, 1)
	m.recvMap.Store(msg.Id, recvCh)
	defer m.recvMap.Delete(msg.Id)

	timer := time.NewTimer(dnsRetryInterval)
	defer timer.Stop()

	for i := range dnsRetryCount {
		if _, err := m.conn.Write(data); err != nil {
			return err
		}
		if i > 0 {
			timer.Reset(dnsRetryInterval)
		}
		select {
		case <-m.ctx.Done():
			return net.ErrClosed
		case <-ctx.Done():
			return context.Canceled
		case recvMsg := <-recvCh:
			// Copy received message to the output message
			*msg = *recvMsg
			return nil
		case <-timer.C:
		}
	}

	var qname string
	var qtype uint16
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
		qtype = msg.Question[0].Qtype
	}
	log.Warnf("dns timeout, stream: %v, qname: %v, qtype: %v", m.stream, qname, qtype)
	return context.DeadlineExceeded
}
