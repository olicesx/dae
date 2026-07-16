/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestPolicySnapshotCompilePreservesLoweringOrder(t *testing.T) {
	snapshot := newCompiledPolicyTestSnapshot(t)
	compiled, err := snapshot.Compile(logrus.New(), map[string]uint8{
		"direct": 1,
		"proxy":  2,
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	plan := compiled.KernelPlan()
	if len(plan.Matches) != 5 {
		t.Fatalf("len(Matches) = %d, want 5", len(plan.Matches))
	}
	if plan.Matches[0].Type != consts.MatchType_DomainSet || plan.Matches[0].Outbound != consts.OutboundLogicalAnd {
		t.Fatalf("first match = %+v, want domain logical-and", plan.Matches[0])
	}
	if plan.Matches[0].DomainKey != consts.RoutingDomainKey_Suffix || !reflect.DeepEqual(plan.Matches[0].Domains, []string{"example.com"}) {
		t.Fatalf("domain match = %+v, want suffix example.com", plan.Matches[0])
	}
	if plan.Matches[1].Type != consts.MatchType_Port || plan.Matches[1].Outbound != consts.OutboundLogicalOr || plan.Matches[1].PortStart != 443 || plan.Matches[1].PortEnd != 443 {
		t.Fatalf("first port match = %+v, want logical-or 443", plan.Matches[1])
	}
	if plan.Matches[2].Type != consts.MatchType_Port || plan.Matches[2].Outbound != 2 || plan.Matches[2].PortStart != 8443 || plan.Matches[2].PortEnd != 8443 || !plan.Matches[2].Must || plan.Matches[2].Mark != 9 {
		t.Fatalf("second port match = %+v, want proxy 8443 mark/must", plan.Matches[2])
	}
	if plan.Matches[3].Type != consts.MatchType_Mac || !plan.Matches[3].Not || plan.Matches[3].Outbound != 1 {
		t.Fatalf("MAC match = %+v, want negative direct MAC", plan.Matches[3])
	}
	if plan.Matches[4].Type != consts.MatchType_Fallback || plan.Matches[4].Outbound != 2 {
		t.Fatalf("fallback match = %+v, want proxy fallback", plan.Matches[4])
	}
	if !plan.PacketMetadataSensitive {
		t.Fatal("PacketMetadataSensitive = false, want true for MAC rule")
	}
	if len(plan.PrefixSets) != 1 || len(plan.PrefixSets[0]) != 2 {
		t.Fatalf("PrefixSets = %+v, want negative MAC set plus zero MAC", plan.PrefixSets)
	}
	if !reflect.DeepEqual(plan.ReferencedOutbounds, []string{"direct", "proxy"}) {
		t.Fatalf("ReferencedOutbounds = %v, want direct/proxy", plan.ReferencedOutbounds)
	}
}

func TestPolicySnapshotCompileCopiesInputsAndPlanViews(t *testing.T) {
	snapshot := newCompiledPolicyTestSnapshot(t)
	bindings := map[string]uint8{"direct": 1, "proxy": 2}
	compiled, err := snapshot.Compile(logrus.New(), bindings)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	originalHash := compiled.Hash()

	bindings["proxy"] = 7
	if got := compiled.OutboundIDs(); !reflect.DeepEqual(got, []OutboundID{{Name: "direct", ID: 1}, {Name: "proxy", ID: 2}}) {
		t.Fatalf("OutboundIDs() = %+v, want copied original bindings", got)
	}
	if got := compiled.Hash(); got != originalHash {
		t.Fatal("compiled hash changed after caller mapping mutation")
	}

	kernelPlan := compiled.KernelPlan()
	kernelPlan.Matches[0].Domains[0] = "mutated.example"
	kernelPlan.PrefixSets[0][0] = kernelPlan.PrefixSets[0][1]
	kernelPlan.ReferencedOutbounds[0] = "mutated"
	userspacePlan := compiled.UserspacePlan()
	if userspacePlan.Matches[0].Domains[0] != "example.com" {
		t.Fatalf("UserspacePlan domain = %q, want immutable source", userspacePlan.Matches[0].Domains[0])
	}
	if userspacePlan.ReferencedOutbounds[0] != "direct" {
		t.Fatalf("UserspacePlan referenced outbound = %q, want immutable source", userspacePlan.ReferencedOutbounds[0])
	}

	recompiled, err := snapshot.Compile(logrus.New(), bindings)
	if err != nil {
		t.Fatalf("Compile() after mapping mutation error = %v", err)
	}
	if recompiled.SourceHash() != compiled.SourceHash() {
		t.Fatalf("SourceHash changed after outbound mapping mutation")
	}
	if recompiled.Hash() == compiled.Hash() {
		t.Fatal("compiled hash did not include outbound ID bindings")
	}
}

func TestPolicySnapshotCompilePreservesPredicateGroupSpans(t *testing.T) {
	snapshot := newCompiledPolicyTestSnapshot(t)
	compiled, err := snapshot.Compile(logrus.New(), map[string]uint8{"direct": 1, "proxy": 2})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	plan := compiled.UserspacePlan()
	want := []PredicateGroupSpan{
		{Name: consts.Function_Domain, Key: string(consts.RoutingDomainKey_Suffix), Start: 0, End: 1},
		{Name: consts.Function_Port, Start: 1, End: 3},
		{Name: consts.Function_Mac, Not: true, Start: 3, End: 4},
	}
	if !reflect.DeepEqual(plan.PredicateGroups, want) {
		t.Fatalf("PredicateGroups = %+v, want %+v", plan.PredicateGroups, want)
	}

	plan.PredicateGroups[0].Name = "mutated"
	if got := compiled.KernelPlan().PredicateGroups[0].Name; got != consts.Function_Domain {
		t.Fatalf("KernelPlan predicate group name = %q, want immutable %q", got, consts.Function_Domain)
	}
}

func TestPolicySnapshotCompileUsesOneOutboundBindingSnapshot(t *testing.T) {
	snapshot := newCompiledPolicyTestSnapshot(t)
	bindings := map[string]uint8{"direct": 1, "proxy": 2}
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	log.AddHook(mutateCompiledPolicyBindingsHook{bindings: bindings})

	compiled, err := snapshot.Compile(log, bindings)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if got := bindings["proxy"]; got != 7 {
		t.Fatalf("hook mutation = %d, want 7", got)
	}
	if got := compiled.OutboundIDs(); !reflect.DeepEqual(got, []OutboundID{{Name: "direct", ID: 1}, {Name: "proxy", ID: 2}}) {
		t.Fatalf("OutboundIDs() = %+v, want compiler binding snapshot", got)
	}
	plan := compiled.KernelPlan()
	if plan.Matches[2].Outbound != 2 || plan.Matches[len(plan.Matches)-1].Outbound != 2 {
		t.Fatalf("compiled proxy IDs = (%d, %d), want binding snapshot ID 2", plan.Matches[2].Outbound, plan.Matches[len(plan.Matches)-1].Outbound)
	}
}

type mutateCompiledPolicyBindingsHook struct {
	bindings map[string]uint8
}

func (h mutateCompiledPolicyBindingsHook) Fire(*logrus.Entry) error {
	h.bindings["proxy"] = 7
	return nil
}

func (h mutateCompiledPolicyBindingsHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.DebugLevel}
}

func newCompiledPolicyTestSnapshot(t *testing.T) *PolicySnapshot {
	t.Helper()
	program, err := NewNormalizedProgram([]*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "example.com",
					}},
				},
				{
					Name:   consts.Function_Port,
					Params: []*config_parser.Param{{Val: "443"}, {Val: "8443"}},
				},
			},
			Outbound: config_parser.Function{
				Name:   "proxy",
				Params: []*config_parser.Param{{Key: consts.OutboundParam_Mark, Val: "9"}, {Val: "must"}},
			},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Mac,
				Not:    true,
				Params: []*config_parser.Param{{Val: "00:11:22:33:44:55"}},
			}},
			Outbound: config_parser.Function{Name: "direct"},
		},
	}, config.FunctionOrString("proxy"))
	if err != nil {
		t.Fatalf("NewNormalizedProgram() error = %v", err)
	}
	snapshot, err := NewPolicySnapshot(13, program)
	if err != nil {
		t.Fatalf("NewPolicySnapshot() error = %v", err)
	}
	return snapshot
}
