/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// LegacyOracle is a test-only, typed representation of an observable legacy
// routing trace. It deliberately does not use PolicySnapshot or Decision: the
// current RoutingMatcher remains the authority being pinned by these vectors.
type LegacyOracle struct {
	traces          []legacyOracleTrace
	sequences       []legacyOracleSequence
	dnsTraces       []legacyOracleDNSTrace
	timedDNSTraces  []legacyOracleTimedDNSTrace
	reloadSequences []legacyReloadOracleSequence
}

type legacyOracleTrace struct {
	Name    string
	Program legacyOracleProgram
	Facts   legacyOracleFacts
	Want    legacyOracleActionTrace
}

type legacyOracleProgram struct {
	Rules       []*config_parser.RoutingRule
	Fallback    config.FunctionOrString
	OutboundIDs map[string]uint8
}

// legacyOracleFacts preserves the complete Phase 0 input vocabulary. The
// RoutingMatcher-only replay consumes the tuple, metadata, and selected domain
// evidence; DNS, health, time, and reload adapters replay the remaining facts
// through their respective legacy paths in this test suite.
type legacyOracleFacts struct {
	Tuple          legacyFiveTuple
	Metadata       legacyMetadata
	DomainEvidence legacyDomainEvidence
	DNSAnswer      legacyDNSAnswer
	Health         legacyHealthState
	At             time.Duration
	Reload         legacyReloadEvent
}

type legacyFiveTuple struct {
	Source  netip.AddrPort
	Dest    netip.AddrPort
	L4Proto consts.L4ProtoType
}

type legacyMetadata struct {
	MAC         [6]uint8
	PID         uint32
	DSCP        uint8
	ProcessName [16]uint8
}

type legacyDomainEvidenceSource uint8

const (
	legacyDomainEvidenceUnknown legacyDomainEvidenceSource = iota
	legacyDomainEvidenceNone
	legacyDomainEvidenceDNS
	legacyDomainEvidenceTLSSNI
	legacyDomainEvidenceQUICSNI
)

// legacyDomainEvidence has exactly one selected fact. A vector must use
// legacyDomainEvidenceNone for an explicitly absent domain rather than mixing
// DNS, TLS, and QUIC evidence in the same routing decision.
type legacyDomainEvidence struct {
	Source legacyDomainEvidenceSource
	Domain string
}

// legacyDNSAnswer keeps both parsed-friendly facts and the original wire
// bytes. RoutingMatcher-only replay does not consume it; the DNS replay
// adapter unpacks the recorded wire and compares its client response output.
type legacyDNSAnswer struct {
	Question string
	RCode    uint16
	Answers  []netip.Addr
	Wire     []byte
}

type legacyHealthState struct {
	Candidate string
	Network   string
	Healthy   bool
}

type legacyReloadKind uint8

const (
	legacyReloadUnknown legacyReloadKind = iota
	legacyReloadNone
	legacyReloadPublished
)

type legacyReloadEvent struct {
	Kind  legacyReloadKind
	Epoch uint64
}

type legacyDisposition uint8

const (
	legacyDispositionUnknown legacyDisposition = iota
	legacyDispositionDirect
	legacyDispositionProxy
	legacyDispositionBlock
)

type legacyFlowState uint8

const (
	legacyFlowStateUnknown legacyFlowState = iota
	legacyFlowStateRouteEvaluated
	legacyFlowStateDirect
	legacyFlowStateProxySelected
	legacyFlowStateEgressBound
	legacyFlowStateBlocked
)

// legacyOracleActionTrace is the fixed golden output for one event. Proxy
// cases execute the legacy dial or endpoint path and therefore carry a target
// and bound-flow transition. Direct/block cases remain matcher-only because
// they do not create a proxy egress binding.
type legacyOracleActionTrace struct {
	Disposition       legacyDisposition
	Outbound          consts.OutboundIndex
	Mark              uint32
	Must              bool
	DialTarget        string
	L4Proto           consts.L4ProtoType
	AddressFamily     consts.IpVersionType
	DNSResponseWire   []byte
	ExecutionResolved bool
	FlowStates        []legacyFlowState
}

func TestLegacyOracle_RoutingMatcherReplay(t *testing.T) {
	oracle := LegacyOracle{traces: legacyOracleRoutingTraces()}
	for _, trace := range oracle.traces {
		trace := trace
		t.Run(trace.Name, func(t *testing.T) {
			if err := validateLegacyOracleTrace(trace); err != nil {
				t.Fatalf("invalid legacy trace: %v", err)
			}

			got, err := oracle.replayRoutingMatcher(t, trace)
			if err != nil {
				t.Fatalf("legacy matcher replay: %v", err)
			}
			if !reflect.DeepEqual(got, trace.Want) {
				t.Fatalf("legacy action trace = %+v, want %+v", got, trace.Want)
			}
		})
	}
}

func TestLegacyOracle_OrderedReplay(t *testing.T) {
	oracle := LegacyOracle{sequences: legacyOracleOrderedSequences()}
	for _, sequence := range oracle.sequences {
		sequence := sequence
		t.Run(sequence.Name, func(t *testing.T) {
			if err := validateLegacyOracleSequence(sequence); err != nil {
				t.Fatalf("invalid legacy sequence: %v", err)
			}

			got, err := oracle.replayOrderedSequence(t, sequence)
			if err != nil {
				t.Fatalf("legacy ordered replay: %v", err)
			}
			if !reflect.DeepEqual(got, sequence.Want) {
				t.Fatalf("legacy ordered action trace = %#v, want %#v", got, sequence.Want)
			}
		})
	}
}

func TestLegacyOracle_DNSReplay(t *testing.T) {
	oracle := LegacyOracle{dnsTraces: legacyOracleDNSTraces()}
	for _, trace := range oracle.dnsTraces {
		trace := trace
		t.Run(trace.Name, func(t *testing.T) {
			if err := validateLegacyOracleDNSTrace(trace); err != nil {
				t.Fatalf("invalid legacy DNS trace: %v", err)
			}

			got, err := oracle.replayDNS(t, trace)
			if err != nil {
				t.Fatalf("legacy DNS replay: %v", err)
			}
			if !reflect.DeepEqual(got, trace.Want) {
				t.Fatalf("legacy DNS action trace = %+v, want %+v", got, trace.Want)
			}
		})
	}
}

func TestLegacyOracle_TimedDNSReplay(t *testing.T) {
	oracle := LegacyOracle{timedDNSTraces: legacyOracleTimedDNSTraces()}
	for _, trace := range oracle.timedDNSTraces {
		trace := trace
		t.Run(trace.Name, func(t *testing.T) {
			if err := validateLegacyOracleTimedDNSTrace(trace); err != nil {
				t.Fatalf("invalid timed legacy DNS trace: %v", err)
			}

			got, err := oracle.replayTimedDNS(t, trace)
			if err != nil {
				t.Fatalf("timed legacy DNS replay: %v", err)
			}
			if !reflect.DeepEqual(got, trace.Want) {
				t.Fatalf("timed legacy DNS action trace = %+v, want %+v", got, trace.Want)
			}
		})
	}
}

func TestLegacyOracle_ReloadReplay(t *testing.T) {
	oracle := LegacyOracle{reloadSequences: legacyOracleReloadSequences()}
	for _, sequence := range oracle.reloadSequences {
		sequence := sequence
		t.Run(sequence.Name, func(t *testing.T) {
			if err := validateLegacyReloadOracleSequence(sequence); err != nil {
				t.Fatalf("invalid legacy reload sequence: %v", err)
			}

			got, err := oracle.replayReloadSequence(t, sequence)
			if err != nil {
				t.Fatalf("legacy reload replay: %v", err)
			}
			if !reflect.DeepEqual(got, sequence.Want) {
				t.Fatalf("legacy reload action trace = %#v, want %#v", got, sequence.Want)
			}
		})
	}
}

func (o LegacyOracle) replayRoutingMatcher(t *testing.T, trace legacyOracleTrace) (legacyOracleActionTrace, error) {
	t.Helper()
	matcher, err := buildLegacyOracleMatcher(trace.Program)
	if err != nil {
		return legacyOracleActionTrace{}, err
	}

	// Route rather than calling matcher.Match directly. This retains the real
	// ControlPlane conversion of MAC, DSCP, and process metadata into legacy
	// matcher inputs. PID remains recorded in the BPF result because it is part
	// of the observable input trace, even though the legacy matcher ignores it.
	routingResult := &bpfRoutingResult{
		Mac:   trace.Facts.Metadata.MAC,
		Pid:   trace.Facts.Metadata.PID,
		Dscp:  trace.Facts.Metadata.DSCP,
		Pname: trace.Facts.Metadata.ProcessName,
	}
	plane := &ControlPlane{
		controlPlaneGenerationState: controlPlaneGenerationState{
			routingMatcher: matcher,
		},
	}
	outbound, mark, must, err := plane.Route(
		trace.Facts.Tuple.Source,
		trace.Facts.Tuple.Dest,
		trace.Facts.DomainEvidence.Domain,
		trace.Facts.Tuple.L4Proto,
		routingResult,
	)
	if err != nil {
		return legacyOracleActionTrace{}, err
	}

	disposition := legacyDispositionForOutbound(outbound)
	traceResult := legacyOracleActionTrace{
		Disposition:       disposition,
		Outbound:          outbound,
		Mark:              mark,
		Must:              must,
		L4Proto:           trace.Facts.Tuple.L4Proto,
		AddressFamily:     legacyIPVersion(trace.Facts.Tuple.Dest.Addr()),
		ExecutionResolved: false,
		FlowStates:        legacyMatcherFlowStates(disposition),
	}

	// Proxy outputs have a concrete legacy execution path. Keep direct/block
	// traces at the matcher boundary because they do not create a proxy dialer
	// binding in the code under test.
	if disposition != legacyDispositionProxy {
		return traceResult, nil
	}
	switch trace.Facts.Tuple.L4Proto {
	case consts.L4ProtoType_TCP:
		return replayLegacyOracleTCP(t, trace, traceResult)
	case consts.L4ProtoType_UDP:
		return replayLegacyOracleUDP(t, trace, traceResult)
	default:
		return legacyOracleActionTrace{}, fmt.Errorf("unsupported proxy protocol %v", trace.Facts.Tuple.L4Proto)
	}
}

func replayLegacyOracleTCP(t *testing.T, trace legacyOracleTrace, result legacyOracleActionTrace) (legacyOracleActionTrace, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close() })

	d := newTestEndpointDialer(clientConn)
	plane := newTestDialControlPlane(newTestFixedOutboundGroup(d))
	conn, dialResult, err := plane.routeDial(context.Background(), &proxyDialParam{
		Outbound:    result.Outbound,
		Must:        result.Must,
		Domain:      trace.Facts.DomainEvidence.Domain,
		Mac:         trace.Facts.Metadata.MAC,
		Dscp:        trace.Facts.Metadata.DSCP,
		ProcessName: trace.Facts.Metadata.ProcessName,
		Src:         trace.Facts.Tuple.Source,
		Dest:        trace.Facts.Tuple.Dest,
		Mark:        result.Mark,
		Network:     "tcp",
	})
	if err != nil {
		return legacyOracleActionTrace{}, fmt.Errorf("routeDial: %w", err)
	}
	if conn == nil || dialResult == nil || dialResult.SelectionNetworkTypeObj == nil {
		return legacyOracleActionTrace{}, fmt.Errorf("routeDial did not return a concrete egress selection")
	}
	defer func() { _ = conn.Close() }()

	family, err := legacyIPVersionFromString(dialResult.SelectionNetworkTypeObj.IpVersion)
	if err != nil {
		return legacyOracleActionTrace{}, err
	}
	if dialResult.Binding.Route.Outbound != dialResult.OutboundIndex ||
		dialResult.Binding.Route.Mark != dialResult.Mark ||
		dialResult.Binding.Route.Must != dialResult.Must ||
		dialResult.Binding.Egress.Target != dialResult.DialTarget ||
		dialResult.Binding.Egress.NetworkType != *dialResult.SelectionNetworkTypeObj {
		return legacyOracleActionTrace{}, fmt.Errorf("routeDial did not retain the selected TCP flow binding")
	}

	result.Outbound = dialResult.OutboundIndex
	result.Mark = dialResult.Mark
	result.Must = dialResult.Must
	result.DialTarget = dialResult.DialTarget
	result.AddressFamily = family
	result.ExecutionResolved = true
	result.FlowStates = append(result.FlowStates, legacyFlowStateEgressBound)
	return result, nil
}

func replayLegacyOracleUDP(t *testing.T, trace legacyOracleTrace, result legacyOracleActionTrace) (legacyOracleActionTrace, error) {
	t.Helper()
	oldPool := DefaultUdpEndpointPool
	pool := NewUdpEndpointPool()
	DefaultUdpEndpointPool = pool
	t.Cleanup(func() {
		pool.Reset()
		DefaultUdpEndpointPool = oldPool
	})

	conn := &udpReuseSimulationConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d, underlay := newCountingProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	plane := newUdpReuseSimulationControlPlane(newTestFixedOutboundGroup(d))
	routingResult := &bpfRoutingResult{
		Outbound: uint8(result.Outbound),
		Mark:     result.Mark,
		Mac:      trace.Facts.Metadata.MAC,
		Dscp:     trace.Facts.Metadata.DSCP,
		Pname:    trace.Facts.Metadata.ProcessName,
		Pid:      trace.Facts.Metadata.PID,
	}
	if result.Must {
		routingResult.Must = 1
	}
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	flowDecision := ClassifyUdpFlow(trace.Facts.Tuple.Source, trace.Facts.Tuple.Dest, payload)
	if flowDecision.IsQuicInitial || flowDecision.AllowsSniffing {
		return legacyOracleActionTrace{}, fmt.Errorf("ordinary UDP vector unexpectedly entered sniffing")
	}
	if err := plane.handlePkt(nil, payload, trace.Facts.Tuple.Source, trace.Facts.Tuple.Dest, routingResult, flowDecision, false); err != nil {
		return legacyOracleActionTrace{}, fmt.Errorf("handlePkt: %w", err)
	}

	endpoint, ok := DefaultUdpEndpointPool.Get(flowDecision.FullConeNatEndpointKey())
	if !ok || endpoint == nil {
		return legacyOracleActionTrace{}, fmt.Errorf("handlePkt did not create a full-cone UDP endpoint")
	}
	defer func() { _ = endpoint.Close() }()
	binding := endpoint.FlowBinding()
	if binding.Route.Outbound != result.Outbound || binding.Route.Mark != result.Mark || binding.Route.Must != result.Must ||
		binding.Egress.Dialer != d || binding.Egress.Target != trace.Facts.Tuple.Dest.String() || binding.Egress.NetworkType.L4Proto != consts.L4ProtoStr_UDP {
		return legacyOracleActionTrace{}, fmt.Errorf("handlePkt did not retain the selected UDP flow binding")
	}
	if got := underlay.calls.Load(); got != 1 {
		return legacyOracleActionTrace{}, fmt.Errorf("UDP dial calls = %d, want 1", got)
	}
	if got := conn.writeCalls.Load(); got != 1 {
		return legacyOracleActionTrace{}, fmt.Errorf("UDP writes = %d, want 1", got)
	}

	family, err := legacyIPVersionFromString(binding.Egress.NetworkType.IpVersion)
	if err != nil {
		return legacyOracleActionTrace{}, err
	}
	result.Outbound = binding.Route.Outbound
	result.Mark = binding.Route.Mark
	result.Must = binding.Route.Must
	result.DialTarget = binding.Egress.Target
	result.AddressFamily = family
	result.ExecutionResolved = true
	result.FlowStates = append(result.FlowStates, legacyFlowStateEgressBound)
	return result, nil
}

func legacyIPVersionFromString(ipVersion consts.IpVersionStr) (consts.IpVersionType, error) {
	switch ipVersion {
	case consts.IpVersionStr_4:
		return consts.IpVersion_4, nil
	case consts.IpVersionStr_6:
		return consts.IpVersion_6, nil
	default:
		return 0, fmt.Errorf("unsupported selected IP version %q", ipVersion)
	}
}

func buildLegacyOracleMatcher(program legacyOracleProgram) (*RoutingMatcher, error) {
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		program.Rules,
		program.OutboundIDs,
		nil,
		program.Fallback,
	)
	if err != nil {
		return nil, err
	}
	return builder.BuildUserspace()
}

func validateLegacyOracleTrace(trace legacyOracleTrace) error {
	facts := trace.Facts
	if !facts.Tuple.Source.IsValid() || !facts.Tuple.Dest.IsValid() {
		return fmt.Errorf("invalid flow tuple")
	}
	if facts.Tuple.L4Proto != consts.L4ProtoType_TCP && facts.Tuple.L4Proto != consts.L4ProtoType_UDP {
		return fmt.Errorf("unsupported L4 protocol %v", facts.Tuple.L4Proto)
	}
	if facts.DomainEvidence.Source == legacyDomainEvidenceUnknown {
		return fmt.Errorf("domain evidence source is unspecified")
	}
	if facts.DomainEvidence.Source == legacyDomainEvidenceNone && facts.DomainEvidence.Domain != "" {
		return fmt.Errorf("absent domain evidence has domain %q", facts.DomainEvidence.Domain)
	}
	if facts.DomainEvidence.Source != legacyDomainEvidenceNone && facts.DomainEvidence.Domain == "" {
		return fmt.Errorf("domain evidence source %d has no domain", facts.DomainEvidence.Source)
	}
	if facts.DNSAnswer.Question == "" || len(facts.DNSAnswer.Wire) == 0 {
		return fmt.Errorf("DNS answer is not recorded")
	}
	if facts.Health.Candidate == "" || facts.Health.Network == "" {
		return fmt.Errorf("health state is not recorded")
	}
	if facts.At < 0 {
		return fmt.Errorf("negative event time")
	}
	if facts.Reload.Kind == legacyReloadUnknown || facts.Reload.Epoch == 0 {
		return fmt.Errorf("reload event is not recorded")
	}
	return nil
}

func legacyDispositionForOutbound(outbound consts.OutboundIndex) legacyDisposition {
	switch outbound {
	case consts.OutboundDirect:
		return legacyDispositionDirect
	case consts.OutboundBlock:
		return legacyDispositionBlock
	default:
		return legacyDispositionProxy
	}
}

func legacyMatcherFlowStates(disposition legacyDisposition) []legacyFlowState {
	switch disposition {
	case legacyDispositionDirect:
		return []legacyFlowState{legacyFlowStateRouteEvaluated, legacyFlowStateDirect}
	case legacyDispositionBlock:
		return []legacyFlowState{legacyFlowStateRouteEvaluated, legacyFlowStateBlocked}
	default:
		return []legacyFlowState{legacyFlowStateRouteEvaluated, legacyFlowStateProxySelected}
	}
}

func legacyIPVersion(addr netip.Addr) consts.IpVersionType {
	if addr.Is4() || addr.Is4In6() {
		return consts.IpVersion_4
	}
	return consts.IpVersion_6
}

func legacyOracleRoutingTraces() []legacyOracleTrace {
	return []legacyOracleTrace{
		{
			Name: "tcp_dns_evidence_proxy_mark_must",
			Program: legacyOracleProgram{
				Rules:       []*config_parser.RoutingRule{legacyOracleDomainRule("api.proxy.test", "proxy", 101, true)},
				Fallback:    config.FunctionOrString("direct"),
				OutboundIDs: legacyOracleOutboundIDs(),
			},
			Facts: legacyOracleFacts{
				Tuple: legacyFiveTuple{
					Source:  netip.MustParseAddrPort("192.0.2.10:42001"),
					Dest:    netip.MustParseAddrPort("198.51.100.20:443"),
					L4Proto: consts.L4ProtoType_TCP,
				},
				Metadata:       legacyMetadata{MAC: [6]uint8{0x02, 0, 0, 0, 0, 1}, PID: 1001, DSCP: 46, ProcessName: legacyProcessName("curl")},
				DomainEvidence: legacyDomainEvidence{Source: legacyDomainEvidenceDNS, Domain: "api.proxy.test"},
				DNSAnswer: legacyDNSAnswer{
					Question: "api.proxy.test.",
					RCode:    0,
					Answers:  []netip.Addr{netip.MustParseAddr("198.51.100.20")},
					Wire:     []byte{0x10, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01},
				},
				Health: legacyHealthState{Candidate: "proxy-a", Network: "tcp4", Healthy: true},
				At:     10 * time.Millisecond,
				Reload: legacyReloadEvent{Kind: legacyReloadNone, Epoch: 7},
			},
			Want: legacyOracleActionTrace{
				Disposition:       legacyDispositionProxy,
				Outbound:          consts.OutboundUserDefinedMin,
				Mark:              101,
				Must:              true,
				DialTarget:        "198.51.100.20:443",
				L4Proto:           consts.L4ProtoType_TCP,
				AddressFamily:     consts.IpVersion_4,
				ExecutionResolved: true,
				FlowStates:        []legacyFlowState{legacyFlowStateRouteEvaluated, legacyFlowStateProxySelected, legacyFlowStateEgressBound},
			},
		},
		{
			Name: "udp_no_domain_evidence_proxy",
			Program: legacyOracleProgram{
				Rules: []*config_parser.RoutingRule{{
					AndFunctions: []*config_parser.Function{{
						Name: consts.Function_L4Proto,
						Params: []*config_parser.Param{{
							Val: "udp",
						}},
					}},
					Outbound: config_parser.Function{Name: "proxy", Params: []*config_parser.Param{{Key: "mark", Val: "19"}}},
				}},
				Fallback:    config.FunctionOrString("direct"),
				OutboundIDs: legacyOracleOutboundIDs(),
			},
			Facts: legacyOracleFacts{
				Tuple: legacyFiveTuple{
					Source:  netip.MustParseAddrPort("192.0.2.11:42002"),
					Dest:    netip.MustParseAddrPort("198.51.100.21:3478"),
					L4Proto: consts.L4ProtoType_UDP,
				},
				Metadata:       legacyMetadata{MAC: [6]uint8{0x02, 0, 0, 0, 0, 2}, PID: 1002, DSCP: 0, ProcessName: legacyProcessName("game")},
				DomainEvidence: legacyDomainEvidence{Source: legacyDomainEvidenceNone},
				DNSAnswer: legacyDNSAnswer{
					Question: "relay.proxy.test.",
					RCode:    0,
					Answers:  []netip.Addr{netip.MustParseAddr("198.51.100.21")},
					Wire:     []byte{0x10, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01},
				},
				Health: legacyHealthState{Candidate: "proxy-a", Network: "udp4", Healthy: true},
				At:     20 * time.Millisecond,
				Reload: legacyReloadEvent{Kind: legacyReloadNone, Epoch: 7},
			},
			Want: legacyOracleActionTrace{
				Disposition:       legacyDispositionProxy,
				Outbound:          consts.OutboundUserDefinedMin,
				Mark:              19,
				DialTarget:        "198.51.100.21:3478",
				L4Proto:           consts.L4ProtoType_UDP,
				AddressFamily:     consts.IpVersion_4,
				ExecutionResolved: true,
				FlowStates:        []legacyFlowState{legacyFlowStateRouteEvaluated, legacyFlowStateProxySelected, legacyFlowStateEgressBound},
			},
		},
		{
			Name: "tcp_tls_sni_proxy_ipv6",
			Program: legacyOracleProgram{
				Rules:       []*config_parser.RoutingRule{legacyOracleDomainRule("secure.tls.test", "proxy", 0, false)},
				Fallback:    config.FunctionOrString("direct"),
				OutboundIDs: legacyOracleOutboundIDs(),
			},
			Facts: legacyOracleFacts{
				Tuple: legacyFiveTuple{
					Source:  netip.MustParseAddrPort("[2001:db8::10]:42003"),
					Dest:    netip.MustParseAddrPort("[2001:db8:1::20]:443"),
					L4Proto: consts.L4ProtoType_TCP,
				},
				Metadata:       legacyMetadata{MAC: [6]uint8{0x02, 0, 0, 0, 0, 3}, PID: 1003, DSCP: 34, ProcessName: legacyProcessName("browser")},
				DomainEvidence: legacyDomainEvidence{Source: legacyDomainEvidenceTLSSNI, Domain: "secure.tls.test"},
				DNSAnswer: legacyDNSAnswer{
					Question: "secure.tls.test.",
					RCode:    0,
					Answers:  []netip.Addr{netip.MustParseAddr("2001:db8:1::20")},
					Wire:     []byte{0x10, 0x03, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01},
				},
				Health: legacyHealthState{Candidate: "proxy-v6", Network: "tcp6", Healthy: true},
				At:     30 * time.Millisecond,
				Reload: legacyReloadEvent{Kind: legacyReloadPublished, Epoch: 8},
			},
			Want: legacyOracleActionTrace{
				Disposition:       legacyDispositionProxy,
				Outbound:          consts.OutboundUserDefinedMin,
				Mark:              0x100,
				DialTarget:        "[2001:db8:1::20]:443",
				L4Proto:           consts.L4ProtoType_TCP,
				AddressFamily:     consts.IpVersion_6,
				ExecutionResolved: true,
				FlowStates:        []legacyFlowState{legacyFlowStateRouteEvaluated, legacyFlowStateProxySelected, legacyFlowStateEgressBound},
			},
		},
		{
			Name: "tcp_reserved_direct",
			Program: legacyOracleProgram{
				Rules:       []*config_parser.RoutingRule{legacyOracleDomainRule("direct.test", "direct", 0, false)},
				Fallback:    config.FunctionOrString("block"),
				OutboundIDs: legacyOracleOutboundIDs(),
			},
			Facts: legacyOracleFacts{
				Tuple: legacyFiveTuple{
					Source:  netip.MustParseAddrPort("192.0.2.12:42004"),
					Dest:    netip.MustParseAddrPort("198.51.100.22:80"),
					L4Proto: consts.L4ProtoType_TCP,
				},
				Metadata:       legacyMetadata{MAC: [6]uint8{0x02, 0, 0, 0, 0, 4}, PID: 1004, DSCP: 8, ProcessName: legacyProcessName("wget")},
				DomainEvidence: legacyDomainEvidence{Source: legacyDomainEvidenceDNS, Domain: "direct.test"},
				DNSAnswer: legacyDNSAnswer{
					Question: "direct.test.",
					RCode:    0,
					Answers:  []netip.Addr{netip.MustParseAddr("198.51.100.22")},
					Wire:     []byte{0x10, 0x04, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01},
				},
				Health: legacyHealthState{Candidate: "direct", Network: "tcp4", Healthy: true},
				At:     40 * time.Millisecond,
				Reload: legacyReloadEvent{Kind: legacyReloadNone, Epoch: 8},
			},
			Want: legacyOracleActionTrace{
				Disposition:   legacyDispositionDirect,
				Outbound:      consts.OutboundDirect,
				L4Proto:       consts.L4ProtoType_TCP,
				AddressFamily: consts.IpVersion_4,
				FlowStates:    []legacyFlowState{legacyFlowStateRouteEvaluated, legacyFlowStateDirect},
			},
		},
		{
			Name: "udp_reserved_block",
			Program: legacyOracleProgram{
				Rules:       []*config_parser.RoutingRule{legacyOracleDomainRule("block.test", "block", 0, false)},
				Fallback:    config.FunctionOrString("direct"),
				OutboundIDs: legacyOracleOutboundIDs(),
			},
			Facts: legacyOracleFacts{
				Tuple: legacyFiveTuple{
					Source:  netip.MustParseAddrPort("192.0.2.13:42005"),
					Dest:    netip.MustParseAddrPort("198.51.100.23:53"),
					L4Proto: consts.L4ProtoType_UDP,
				},
				Metadata:       legacyMetadata{MAC: [6]uint8{0x02, 0, 0, 0, 0, 5}, PID: 1005, DSCP: 0, ProcessName: legacyProcessName("dnsmasq")},
				DomainEvidence: legacyDomainEvidence{Source: legacyDomainEvidenceDNS, Domain: "block.test"},
				DNSAnswer: legacyDNSAnswer{
					Question: "block.test.",
					RCode:    3,
					Wire:     []byte{0x10, 0x05, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00},
				},
				Health: legacyHealthState{Candidate: "block", Network: "udp4", Healthy: true},
				At:     50 * time.Millisecond,
				Reload: legacyReloadEvent{Kind: legacyReloadNone, Epoch: 8},
			},
			Want: legacyOracleActionTrace{
				Disposition:   legacyDispositionBlock,
				Outbound:      consts.OutboundBlock,
				L4Proto:       consts.L4ProtoType_UDP,
				AddressFamily: consts.IpVersion_4,
				FlowStates:    []legacyFlowState{legacyFlowStateRouteEvaluated, legacyFlowStateBlocked},
			},
		},
	}
}

func legacyOracleOutboundIDs() map[string]uint8 {
	return map[string]uint8{
		"direct": uint8(consts.OutboundDirect),
		"block":  uint8(consts.OutboundBlock),
		"proxy":  uint8(consts.OutboundUserDefinedMin),
	}
}

func legacyOracleDomainRule(domain, outbound string, mark uint32, must bool) *config_parser.RoutingRule {
	params := make([]*config_parser.Param, 0, 2)
	if mark != 0 {
		params = append(params, &config_parser.Param{Key: "mark", Val: fmt.Sprintf("%d", mark)})
	}
	if must {
		params = append(params, &config_parser.Param{Val: "must"})
	}
	return &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{{
			Name: consts.Function_Domain,
			Params: []*config_parser.Param{{
				Key: string(consts.RoutingDomainKey_Full),
				Val: domain,
			}},
		}},
		Outbound: config_parser.Function{Name: outbound, Params: params},
	}
}

func legacyProcessName(name string) [16]uint8 {
	var processName [16]uint8
	copy(processName[:], name)
	return processName
}
