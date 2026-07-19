/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sort"
	"strconv"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// OutboundID is one copied name-to-ID binding used while compiling a policy.
type OutboundID struct {
	Name string
	ID   consts.OutboundIndex
}

// LoweredMatch is one ordered, backend-neutral routing match operation.
// PrefixSetIndex applies to IP, source-IP, and MAC operations. DomainKey and
// Domains apply to domain operations. The remaining payload fields are used by
// their matching function counterparts.
type LoweredMatch struct {
	Type           consts.MatchType
	Not            bool
	Outbound       consts.OutboundIndex
	Mark           uint32
	Must           bool
	DomainKey      consts.RoutingDomainKey
	Domains        []string
	PrefixSetIndex uint32
	PortStart      uint16
	PortEnd        uint16
	Mask           uint8
	ProcessName    [consts.TaskCommLen]byte
	DSCP           uint8
}

// PredicateGroupSpan maps one normalized predicate group to its lowered match
// operations. The span is recorded at the RulesBuilder parser boundary because
// logical outbound markers alone do not preserve every parameter-key boundary.
type PredicateGroupSpan struct {
	Name  string
	Key   string
	Not   bool
	Start int
	End   int
}

// CompiledPolicyPlan is an immutable-plan view returned by CompiledPolicy.
// Callers receive a deep copy, so mutating the view cannot affect the policy.
type CompiledPolicyPlan struct {
	Matches                    []LoweredMatch
	PredicateGroups            []PredicateGroupSpan
	PrefixSets                 [][]netip.Prefix
	DeduplicatedPrefixSetCount int
	ReferencedOutbounds        []string
	PacketMetadataSensitive    bool
}

// CompiledPolicy is an immutable, backend-neutral lowering of a policy
// snapshot. It intentionally does not carry BPF handles, listeners, or
// dialers; control-plane adapters own those runtime resources.
type CompiledPolicy struct {
	epoch       PolicyEpoch
	sourceHash  [sha256.Size]byte
	hash        [sha256.Size]byte
	outboundIDs []OutboundID
	plan        CompiledPolicyPlan
}

// Compile lowers this snapshot through a copied outbound-ID table. The result
// preserves the legacy RulesBuilder traversal and logical-operation order.
func (s *PolicySnapshot) Compile(log *logrus.Logger, outboundName2ID map[string]uint8) (*CompiledPolicy, error) {
	if s == nil || s.program == nil {
		return nil, fmt.Errorf("nil policy snapshot")
	}
	if log == nil {
		log = logrus.New()
	}

	collector := newCompiledPolicyCollector(outboundName2ID)
	if err := s.program.Lower(log, collector.registerParsers, collector.addFallback); err != nil {
		return nil, err
	}
	if len(collector.matches) > consts.MaxMatchSetLen {
		return nil, fmt.Errorf("too many routing match sets: %d > %d", len(collector.matches), consts.MaxMatchSetLen)
	}
	if len(collector.matches) == 0 || collector.matches[len(collector.matches)-1].Type != consts.MatchType_Fallback {
		return nil, fmt.Errorf("fallback rule MUST be the last")
	}

	plan := collector.plan()
	outboundIDs := copiedOutboundIDs(collector.outboundName2ID)
	compiledHash := hashCompiledPolicy(outboundIDs, plan)

	return &CompiledPolicy{
		epoch:       s.Epoch(),
		sourceHash:  s.Hash(),
		hash:        compiledHash,
		outboundIDs: outboundIDs,
		plan:        plan,
	}, nil
}

// Epoch returns the generation identifier of the source snapshot.
func (p *CompiledPolicy) Epoch() PolicyEpoch {
	if p == nil {
		return 0
	}
	return p.epoch
}

// SourceHash returns the semantic hash of the source policy snapshot.
func (p *CompiledPolicy) SourceHash() [sha256.Size]byte {
	if p == nil {
		return [sha256.Size]byte{}
	}
	return p.sourceHash
}

// Hash returns the hash of the compiled policy layout and copied outbound IDs.
func (p *CompiledPolicy) Hash() [sha256.Size]byte {
	if p == nil {
		return [sha256.Size]byte{}
	}
	return p.hash
}

// OutboundIDs returns an independent copy of the compiler's outbound bindings.
func (p *CompiledPolicy) OutboundIDs() []OutboundID {
	if p == nil {
		return nil
	}
	return append([]OutboundID(nil), p.outboundIDs...)
}

// KernelPlan returns a deep-copy view for a kernel-space adapter.
func (p *CompiledPolicy) KernelPlan() CompiledPolicyPlan {
	if p == nil {
		return CompiledPolicyPlan{}
	}
	return cloneCompiledPolicyPlan(p.plan)
}

// UserspacePlan returns a deep-copy view for a userspace matcher adapter.
func (p *CompiledPolicy) UserspacePlan() CompiledPolicyPlan {
	if p == nil {
		return CompiledPolicyPlan{}
	}
	return cloneCompiledPolicyPlan(p.plan)
}

// PlanView returns a borrowed read-only view of the compiled plan.
// Callers must not mutate the returned slices or any nested slice.
func (p *CompiledPolicy) PlanView() CompiledPolicyPlan {
	if p == nil {
		return CompiledPolicyPlan{}
	}
	return p.plan
}

type compiledPolicyCollector struct {
	outboundName2ID map[string]uint8
	matches         []LoweredMatch
	predicateGroups []PredicateGroupSpan
	prefixSets      [][]netip.Prefix
	lpmDedup        map[uint64]compiledPrefixSet
	referenced      map[string]struct{}
	metadata        bool
}

type compiledPrefixSet struct {
	index    uint32
	prefixes []netip.Prefix
}

func newCompiledPolicyCollector(outboundName2ID map[string]uint8) *compiledPolicyCollector {
	bindings := make(map[string]uint8, len(outboundName2ID))
	for name, id := range outboundName2ID {
		bindings[name] = id
	}
	return &compiledPolicyCollector{
		outboundName2ID: bindings,
		lpmDedup:        make(map[uint64]compiledPrefixSet),
		referenced:      make(map[string]struct{}),
	}
}

func (c *compiledPolicyCollector) registerParsers(builder *RulesBuilder) {
	c.registerParser(builder, consts.Function_Domain, PlainParserFactory(c.addDomain))
	c.registerParser(builder, consts.Function_Ip, IpParserFactory(c.addIP))
	c.registerParser(builder, consts.Function_SourceIp, IpParserFactory(c.addSourceIP))
	c.registerParser(builder, consts.Function_Port, PortRangeParserFactory(c.addPort))
	c.registerParser(builder, consts.Function_SourcePort, PortRangeParserFactory(c.addSourcePort))
	c.registerParser(builder, consts.Function_L4Proto, L4ProtoParserFactory(c.addL4Proto))
	c.registerParser(builder, consts.Function_Mac, MacParserFactory(c.addMAC))
	c.registerParser(builder, consts.Function_ProcessName, ProcessNameParserFactory(c.addProcessName))
	c.registerParser(builder, consts.Function_Dscp, UintParserFactory(c.addDSCP))
	c.registerParser(builder, consts.Function_IpVersion, IpVersionParserFactory(c.addIPVersion))
}

func (c *compiledPolicyCollector) registerParser(builder *RulesBuilder, name string, parser FunctionParser) {
	builder.RegisterFunctionParser(name, func(
		log *logrus.Logger,
		function *config_parser.Function,
		key string,
		values []string,
		overrideOutbound *Outbound,
	) error {
		start := len(c.matches)
		if err := parser(log, function, key, values, overrideOutbound); err != nil {
			return err
		}
		c.predicateGroups = append(c.predicateGroups, PredicateGroupSpan{
			Name:  function.Name,
			Key:   key,
			Not:   function.Not,
			Start: start,
			End:   len(c.matches),
		})
		return nil
	})
}

func (c *compiledPolicyCollector) outboundID(name string) (consts.OutboundIndex, error) {
	switch name {
	case consts.OutboundLogicalOr.String():
		return consts.OutboundLogicalOr, nil
	case consts.OutboundLogicalAnd.String():
		return consts.OutboundLogicalAnd, nil
	case consts.OutboundMustRules.String():
		return consts.OutboundMustRules, nil
	default:
		id, ok := c.outboundName2ID[name]
		if !ok {
			return 0, fmt.Errorf("outbound (group) %v not found; please define it in section \"group\"", strconv.Quote(name))
		}
		c.referenced[name] = struct{}{}
		return consts.OutboundIndex(id), nil
	}
}

func (c *compiledPolicyCollector) appendMatch(match LoweredMatch) {
	c.matches = append(c.matches, match)
}

func (c *compiledPolicyCollector) newMatch(matchType consts.MatchType, f *config_parser.Function, outbound *Outbound) (LoweredMatch, error) {
	id, err := c.outboundID(outbound.Name)
	if err != nil {
		return LoweredMatch{}, err
	}
	return LoweredMatch{
		Type:     matchType,
		Not:      f.Not,
		Outbound: id,
		Mark:     outbound.Mark,
		Must:     outbound.Must,
	}, nil
}

func (c *compiledPolicyCollector) addDomain(f *config_parser.Function, key string, values []string, outbound *Outbound) error {
	domainKey := consts.RoutingDomainKey(key)
	switch domainKey {
	case consts.RoutingDomainKey_Regex,
		consts.RoutingDomainKey_Full,
		consts.RoutingDomainKey_Keyword,
		consts.RoutingDomainKey_Suffix:
	default:
		return fmt.Errorf("addDomain: unsupported key: %v", key)
	}
	match, err := c.newMatch(consts.MatchType_DomainSet, f, outbound)
	if err != nil {
		return err
	}
	match.DomainKey = domainKey
	match.Domains = append([]string(nil), values...)
	c.appendMatch(match)
	return nil
}

func (c *compiledPolicyCollector) addIP(f *config_parser.Function, prefixes []netip.Prefix, outbound *Outbound) error {
	return c.addPrefixMatch(consts.MatchType_IpSet, f, prefixes, outbound, true)
}

func (c *compiledPolicyCollector) addSourceIP(f *config_parser.Function, prefixes []netip.Prefix, outbound *Outbound) error {
	return c.addPrefixMatch(consts.MatchType_SourceIpSet, f, prefixes, outbound, true)
}

func (c *compiledPolicyCollector) addMAC(f *config_parser.Function, macs [][6]byte, outbound *Outbound) error {
	if f.Not {
		macs = append(macs, [6]byte{})
	}
	prefixes := make([]netip.Prefix, 0, len(macs))
	for _, mac := range macs {
		var addr [16]byte
		copy(addr[10:], mac[:])
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(addr), 128))
	}
	c.metadata = true
	return c.addPrefixMatch(consts.MatchType_Mac, f, prefixes, outbound, false)
}

func (c *compiledPolicyCollector) addPrefixMatch(matchType consts.MatchType, f *config_parser.Function, prefixes []netip.Prefix, outbound *Outbound, deduplicate bool) error {
	match, err := c.newMatch(matchType, f, outbound)
	if err != nil {
		return err
	}
	match.PrefixSetIndex = c.addPrefixSet(prefixes, deduplicate)
	c.appendMatch(match)
	return nil
}

func (c *compiledPolicyCollector) addPrefixSet(prefixes []netip.Prefix, deduplicate bool) uint32 {
	if deduplicate {
		prefixes = canonicalizeCompiledPrefixes(prefixes)
		hash := hashCompiledPrefixSet(prefixes)
		if previous, ok := c.lpmDedup[hash]; ok && compiledPrefixesEqual(previous.prefixes, prefixes) {
			return previous.index
		}
		index := uint32(len(c.prefixSets))
		stored := append([]netip.Prefix(nil), prefixes...)
		c.prefixSets = append(c.prefixSets, stored)
		c.lpmDedup[hash] = compiledPrefixSet{index: index, prefixes: stored}
		return index
	}

	index := uint32(len(c.prefixSets))
	c.prefixSets = append(c.prefixSets, append([]netip.Prefix(nil), prefixes...))
	return index
}

func (c *compiledPolicyCollector) addPort(f *config_parser.Function, ranges [][2]uint16, outbound *Outbound) error {
	return c.addPortMatches(consts.MatchType_Port, f, ranges, outbound)
}

func (c *compiledPolicyCollector) addSourcePort(f *config_parser.Function, ranges [][2]uint16, outbound *Outbound) error {
	return c.addPortMatches(consts.MatchType_SourcePort, f, ranges, outbound)
}

func (c *compiledPolicyCollector) addPortMatches(matchType consts.MatchType, f *config_parser.Function, ranges [][2]uint16, outbound *Outbound) error {
	for i, portRange := range ranges {
		name := consts.OutboundLogicalOr.String()
		if i == len(ranges)-1 {
			name = outbound.Name
		}
		match, err := c.newMatch(matchType, f, &Outbound{Name: name, Mark: outbound.Mark, Must: outbound.Must})
		if err != nil {
			return err
		}
		match.PortStart = portRange[0]
		match.PortEnd = portRange[1]
		c.appendMatch(match)
	}
	return nil
}

func (c *compiledPolicyCollector) addL4Proto(f *config_parser.Function, protocols consts.L4ProtoType, outbound *Outbound) error {
	match, err := c.newMatch(consts.MatchType_L4Proto, f, outbound)
	if err != nil {
		return err
	}
	match.Mask = uint8(protocols)
	c.appendMatch(match)
	return nil
}

func (c *compiledPolicyCollector) addIPVersion(f *config_parser.Function, versions consts.IpVersionType, outbound *Outbound) error {
	match, err := c.newMatch(consts.MatchType_IpVersion, f, outbound)
	if err != nil {
		return err
	}
	match.Mask = uint8(versions)
	c.appendMatch(match)
	return nil
}

func (c *compiledPolicyCollector) addProcessName(f *config_parser.Function, names [][consts.TaskCommLen]byte, outbound *Outbound) error {
	c.metadata = true
	for i, name := range names {
		outboundName := consts.OutboundLogicalOr.String()
		if i == len(names)-1 {
			outboundName = outbound.Name
		}
		match, err := c.newMatch(consts.MatchType_ProcessName, f, &Outbound{Name: outboundName, Mark: outbound.Mark, Must: outbound.Must})
		if err != nil {
			return err
		}
		match.ProcessName = name
		c.appendMatch(match)
	}
	return nil
}

func (c *compiledPolicyCollector) addDSCP(f *config_parser.Function, values []uint8, outbound *Outbound) error {
	c.metadata = true
	for i, value := range values {
		outboundName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			outboundName = outbound.Name
		}
		match, err := c.newMatch(consts.MatchType_Dscp, f, &Outbound{Name: outboundName, Mark: outbound.Mark, Must: outbound.Must})
		if err != nil {
			return err
		}
		match.DSCP = value
		c.appendMatch(match)
	}
	return nil
}

func (c *compiledPolicyCollector) addFallback(raw config.FunctionOrString) error {
	fallback, err := config.ParseFunctionOrString(raw)
	if err != nil {
		return err
	}
	outbound, err := ParseOutbound(fallback)
	if err != nil {
		return err
	}
	id, err := c.outboundID(outbound.Name)
	if err != nil {
		return err
	}
	c.appendMatch(LoweredMatch{
		Type:     consts.MatchType_Fallback,
		Outbound: id,
		Mark:     outbound.Mark,
		Must:     outbound.Must,
	})
	return nil
}

func (c *compiledPolicyCollector) plan() CompiledPolicyPlan {
	referenced := make([]string, 0, len(c.referenced))
	for name := range c.referenced {
		referenced = append(referenced, name)
	}
	sort.Strings(referenced)
	return CompiledPolicyPlan{
		Matches:                    c.matches,
		PredicateGroups:            c.predicateGroups,
		PrefixSets:                 c.prefixSets,
		DeduplicatedPrefixSetCount: len(c.lpmDedup),
		ReferencedOutbounds:        referenced,
		PacketMetadataSensitive:    c.metadata,
	}
}

func copiedOutboundIDs(bindings map[string]uint8) []OutboundID {
	ids := make([]OutboundID, 0, len(bindings))
	for name, id := range bindings {
		ids = append(ids, OutboundID{Name: name, ID: consts.OutboundIndex(id)})
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].Name < ids[j].Name })
	return ids
}

func cloneCompiledPolicyPlan(plan CompiledPolicyPlan) CompiledPolicyPlan {
	cloned := CompiledPolicyPlan{
		Matches:                    make([]LoweredMatch, len(plan.Matches)),
		PredicateGroups:            append([]PredicateGroupSpan(nil), plan.PredicateGroups...),
		PrefixSets:                 make([][]netip.Prefix, len(plan.PrefixSets)),
		DeduplicatedPrefixSetCount: plan.DeduplicatedPrefixSetCount,
		ReferencedOutbounds:        append([]string(nil), plan.ReferencedOutbounds...),
		PacketMetadataSensitive:    plan.PacketMetadataSensitive,
	}
	for i, match := range plan.Matches {
		cloned.Matches[i] = match
		cloned.Matches[i].Domains = append([]string(nil), match.Domains...)
	}
	for i, prefixes := range plan.PrefixSets {
		cloned.PrefixSets[i] = append([]netip.Prefix(nil), prefixes...)
	}
	return cloned
}

func canonicalizeCompiledPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	canonical := append([]netip.Prefix(nil), prefixes...)
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Bits() != canonical[j].Bits() {
			return canonical[i].Bits() < canonical[j].Bits()
		}
		return canonical[i].Addr().Less(canonical[j].Addr())
	})
	deduplicated := canonical[:0]
	for _, prefix := range canonical {
		if len(deduplicated) == 0 || deduplicated[len(deduplicated)-1] != prefix {
			deduplicated = append(deduplicated, prefix)
		}
	}
	return deduplicated
}

func hashCompiledPrefixSet(prefixes []netip.Prefix) uint64 {
	const (
		fnvOffsetBasis uint64 = 14695981039346656037
		fnvPrime       uint64 = 1099511628211
	)
	hash := fnvOffsetBasis
	for _, prefix := range prefixes {
		hash ^= uint64(prefix.Bits())
		hash *= fnvPrime
		for _, byteValue := range prefix.Addr().AsSlice() {
			hash ^= uint64(byteValue)
			hash *= fnvPrime
		}
	}
	return hash
}

func compiledPrefixesEqual(left, right []netip.Prefix) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
