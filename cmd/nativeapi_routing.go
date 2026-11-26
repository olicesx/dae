/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
)

func (p *nativeAPIProvider) RoutingTraceAvailable() bool {
	plane, err := p.activeControlPlane()
	return err == nil && plane.RoutingTraceAvailable()
}

// RoutingTraceLiveAvailable reports whether the active generation can run DNS
// without touching the runtime DNS controller or dialers.
func (p *nativeAPIProvider) RoutingTraceLiveAvailable() bool {
	generation := p.supervisor.activeSnapshot()
	return generation != nil && generation.traceDNS != nil
}

func (p *nativeAPIProvider) TraceRouting(ctx context.Context, request nativeapi.RoutingTraceRequest) (nativeapi.RoutingTraceResponse, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.RoutingTraceResponse{}, err
	}
	generation := p.supervisor.activeSnapshot()
	if generation == nil || generation.controlPlane == nil {
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(http.StatusServiceUnavailable, "snapshot_unavailable", "routing trace snapshot is unavailable")
	}
	plane := generation.controlPlane
	if !plane.RoutingTraceAvailable() {
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(http.StatusServiceUnavailable, "snapshot_unavailable", "routing trace snapshot is unavailable")
	}
	generationID, steps := plane.RoutingTraceBounds()
	if generationID == "" {
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(http.StatusServiceUnavailable, "snapshot_unavailable", "routing trace snapshot is unavailable")
	}
	var network consts.L4ProtoType
	switch request.Input.Network {
	case "tcp":
		network = consts.L4ProtoType_TCP
	case "udp":
		network = consts.L4ProtoType_UDP
	default:
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(400, "invalid_request", "network must be tcp or udp")
	}
	dstIP, err := nativeTraceIP(request.Input.DstIP)
	if err != nil {
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(400, "invalid_request", "dst_ip must be a valid IP address")
	}
	srcIP, err := nativeTraceIP(request.Input.SrcIP)
	if err != nil {
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(400, "invalid_request", "src_ip must be a valid IP address")
	}
	input := control.RoutingTraceInput{
		Network: network,
		Domain:  request.Input.Domain,
		DstIP:   dstIP,
		DstPort: request.Input.DstPort,
		SrcIP:   srcIP,
		SrcPort: request.Input.SrcPort,
		Pname:   request.Input.Pname,
		Dscp:    request.Input.Dscp,
	}
	traceCtx, cancel := context.WithTimeout(ctx, time.Duration(nativeapi.RoutingTraceTimeoutMs)*time.Millisecond)
	defer cancel()
	destinations := []*netip.Addr{input.DstIP}
	dnsResults := []nativeapi.SimulationDNSData{}
	switch request.Resolve {
	case "", "none":
	case "live":
		if input.Domain == nil || input.DstIP != nil {
			return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(http.StatusUnprocessableEntity, "unsupported_value", "resolve=live requires domain and dst_ip must be null")
		}
		resolver := generation.traceDNS
		if resolver == nil {
			return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(http.StatusUnprocessableEntity, "unsupported_value", "live DNS is unavailable for this routing generation")
		}
		// The runtime routes a DNS upstream query by the requesting client's
		// source address and packet metadata, so the lookup is made for the
		// traced client.
		dnsInput := control.TraceDNSInput{Pname: input.Pname, Dscp: input.Dscp}
		if srcIP != nil {
			dnsInput.Src = netip.AddrPortFrom(*srcIP, 0)
			if input.SrcPort != nil {
				dnsInput.Src = netip.AddrPortFrom(*srcIP, *input.SrcPort)
			}
		}
		lookups, err := resolver.Lookup(traceCtx, *input.Domain, dnsInput)
		if err != nil {
			return nativeapi.RoutingTraceResponse{}, routingTraceError(err)
		}
		destinations, dnsResults, err = projectRoutingTraceDNS(lookups, steps)
		if err != nil {
			return nativeapi.RoutingTraceResponse{}, err
		}
	default:
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(http.StatusUnprocessableEntity, "unsupported_value", "resolve mode is not supported by this engine")
	}
	if len(destinations)*steps > nativeapi.MaxRoutingTraceRuleSteps {
		return nativeapi.RoutingTraceResponse{}, nativeapi.NewAPIError(http.StatusRequestEntityTooLarge, "request_too_large", "routing trace exceeds the configured rule-step limit")
	}
	response := nativeapi.RoutingTraceResponse{
		Mode: "simulation", InstanceID: p.status.snapshot().InstanceID,
		GenerationID: generationID, ObservedAt: time.Now().UTC().Format(time.RFC3339),
		Evaluations: make([]nativeapi.RoutingEvaluation, 0, len(destinations)), DNS: dnsResults,
	}
	for _, destination := range destinations {
		input.DstIP = destination
		evaluation, err := plane.TraceRouting(traceCtx, input)
		if err != nil {
			return nativeapi.RoutingTraceResponse{}, routingTraceError(err)
		}
		response.Evaluations = append(response.Evaluations, projectRoutingEvaluation(evaluation))
	}
	if err := traceCtx.Err(); err != nil {
		return nativeapi.RoutingTraceResponse{}, routingTraceError(err)
	}
	return response, nil
}

func routingTraceError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return nativeapi.NewAPIError(http.StatusServiceUnavailable, "temporarily_unavailable", "routing trace timed out")
	}
	// The traced generation retired before its live lookup could finish.
	var policyErr *control.TraceDNSPolicyError
	if errors.As(err, &policyErr) {
		return nativeapi.NewAPIError(http.StatusServiceUnavailable, "temporarily_unavailable", policyErr.Reason)
	}
	return err
}

func projectRoutingTraceDNS(lookups []control.TraceDNSResult, steps int) ([]*netip.Addr, []nativeapi.SimulationDNSData, error) {
	seen := make(map[netip.Addr]struct{})
	destinations := make([]*netip.Addr, 0, nativeapi.RoutingTraceMaxAddresses)
	dns := make([]nativeapi.SimulationDNSData, 0, len(lookups))
	for i, lookup := range lookups {
		data := nativeapi.SimulationDNSData{
			LookupID: "lookup:" + strconv.Itoa(i+1), Purpose: "dial_target",
			Name: lookup.Question.Name, QType: control.QtypeToString(lookup.Question.Qtype),
			Source: "unknown", Cache: "bypass", Status: lookup.Status,
			RouteEvaluationIDs: []string{}, Addresses: []string{},
		}
		if lookup.Upstream != "" {
			data.Source = "upstream"
			data.Upstream = &lookup.Upstream
		}
		if lookup.UpstreamTransport != "" {
			data.UpstreamTransport = &lookup.UpstreamTransport
		}
		if lookup.CarrierTransport != "" {
			data.CarrierTransport = &lookup.CarrierTransport
		}
		if lookup.Status == "ERROR" || lookup.Status == "TIMEOUT" {
			// The reason is written by the resolver for clients: it names
			// inputs, outbounds and policy, never a node or its credentials.
			data.Error = new("DNS lookup " + lookup.Status + ": " + lookup.Reason)
		}
		lookupSeen := make(map[netip.Addr]struct{})
		for _, address := range lookup.Addresses {
			if _, exists := lookupSeen[address]; !exists {
				lookupSeen[address] = struct{}{}
				data.Addresses = append(data.Addresses, address.String())
			}
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			if len(seen) > nativeapi.RoutingTraceMaxAddresses || len(seen)*steps > nativeapi.MaxRoutingTraceRuleSteps {
				return nil, nil, nativeapi.NewAPIError(http.StatusRequestEntityTooLarge, "request_too_large", "routing trace exceeds the configured address or rule-step limit")
			}
			destinations = append(destinations, &address)
		}
		dns = append(dns, data)
	}
	return destinations, dns, nil
}

func projectRoutingEvaluation(evaluation control.RoutingTraceEvaluation) nativeapi.RoutingEvaluation {
	result := nativeapi.RoutingEvaluation{
		DstIP: evaluation.DstIP, Decision: evaluation.Decision, Outbound: evaluation.Outbound,
		MissingInputs: evaluation.MissingInputs, Rules: make([]nativeapi.RuleEvaluation, 0, len(evaluation.Rules)),
	}
	for _, rule := range evaluation.Rules {
		projected := nativeapi.RuleEvaluation{
			RuleID:        rule.RuleID,
			Expression:    rule.Expression,
			Result:        rule.Result,
			MissingInputs: rule.MissingInputs,
			Conditions:    make([]nativeapi.RuleCondition, 0, len(rule.Conditions)),
		}
		for _, condition := range rule.Conditions {
			projected.Conditions = append(projected.Conditions, nativeapi.RuleCondition{
				ID:            condition.ID,
				Expression:    condition.Expression,
				Result:        condition.Result,
				MissingInputs: condition.MissingInputs,
			})
		}
		result.Rules = append(result.Rules, projected)
	}
	return result
}

func nativeTraceIP(value *string) (*netip.Addr, error) {
	if value == nil {
		return nil, nil
	}
	address, err := netip.ParseAddr(*value)
	if err != nil || address.Zone() != "" {
		return nil, strconv.ErrSyntax
	}
	return &address, nil
}

var _ nativeapi.RulesProvider = (*nativeAPIProvider)(nil)
