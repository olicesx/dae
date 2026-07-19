/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"net/netip"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

const (
	normalizedPolicyHashSchema = "dae.normalized-policy.v1"
	compiledPolicyHashSchema   = "dae.compiled-policy.v1"
)

type canonicalPolicyHasher struct {
	digest   hash.Hash
	scratch  [8]byte
	buffer   [1024]byte
	buffered int
}

func newCanonicalPolicyHasher(schema string) *canonicalPolicyHasher {
	hasher := &canonicalPolicyHasher{digest: sha256.New()}
	hasher.writeString(schema)
	return hasher
}

func (h *canonicalPolicyHasher) sum() (sum [sha256.Size]byte) {
	h.flush()
	h.digest.Sum(sum[:0])
	return sum
}

func (h *canonicalPolicyHasher) writeByte(value byte) {
	if h.buffered == len(h.buffer) {
		h.flush()
	}
	h.buffer[h.buffered] = value
	h.buffered++
}

func (h *canonicalPolicyHasher) writeBool(value bool) {
	if value {
		h.writeByte(1)
		return
	}
	h.writeByte(0)
}

func (h *canonicalPolicyHasher) writeUint64(value uint64) {
	if len(h.buffer)-h.buffered >= len(h.scratch) {
		binary.LittleEndian.PutUint64(h.buffer[h.buffered:], value)
		h.buffered += len(h.scratch)
		return
	}
	binary.LittleEndian.PutUint64(h.scratch[:], value)
	h.writeRawBytes(h.scratch[:])
}

func (h *canonicalPolicyHasher) writeInt(value int) {
	h.writeUint64(uint64(int64(value)))
}

func (h *canonicalPolicyHasher) writeString(value string) {
	h.writeUint64(uint64(len(value)))
	h.writeRawString(value)
}

func (h *canonicalPolicyHasher) writeBytes(value []byte) {
	h.writeUint64(uint64(len(value)))
	h.writeRawBytes(value)
}

func (h *canonicalPolicyHasher) writeRawString(value string) {
	for len(value) > 0 {
		if h.buffered == len(h.buffer) {
			h.flush()
		}
		written := copy(h.buffer[h.buffered:], value)
		h.buffered += written
		value = value[written:]
	}
}

func (h *canonicalPolicyHasher) writeRawBytes(value []byte) {
	for len(value) > 0 {
		if h.buffered == len(h.buffer) {
			h.flush()
		}
		written := copy(h.buffer[h.buffered:], value)
		h.buffered += written
		value = value[written:]
	}
}

func (h *canonicalPolicyHasher) flush() {
	if h.buffered == 0 {
		return
	}
	_, _ = h.digest.Write(h.buffer[:h.buffered])
	h.buffered = 0
}

func (h *canonicalPolicyHasher) writeFunction(function *config_parser.Function) {
	if function == nil {
		h.writeByte(0)
		return
	}
	h.writeByte(1)
	h.writeFunctionValue(function)
}

func (h *canonicalPolicyHasher) writeFunctionValue(function *config_parser.Function) {
	h.writeString(function.Name)
	h.writeBool(function.Not)
	h.writeParams(function.Params)
}

func (h *canonicalPolicyHasher) writeFunctions(functions []*config_parser.Function) {
	h.writeBool(functions != nil)
	h.writeUint64(uint64(len(functions)))
	for _, function := range functions {
		h.writeFunction(function)
	}
}

func (h *canonicalPolicyHasher) writeParam(param *config_parser.Param) {
	if param == nil {
		h.writeByte(0)
		return
	}
	h.writeByte(1)
	h.writeString(param.Key)
	h.writeString(param.Val)
	h.writeFunctions(param.AndFunctions)
	h.writeParams(param.Annotation)
}

func (h *canonicalPolicyHasher) writeParams(params []*config_parser.Param) {
	h.writeBool(params != nil)
	h.writeUint64(uint64(len(params)))
	for _, param := range params {
		h.writeParam(param)
	}
}

func (h *canonicalPolicyHasher) writeRules(rules []*config_parser.RoutingRule) {
	h.writeBool(rules != nil)
	h.writeUint64(uint64(len(rules)))
	for _, rule := range rules {
		if rule == nil {
			h.writeByte(0)
			continue
		}
		h.writeByte(1)
		h.writeFunctions(rule.AndFunctions)
		h.writeFunctionValue(&rule.Outbound)
	}
}

func (h *canonicalPolicyHasher) writeFallback(fallback config.FunctionOrString) error {
	switch fallback := fallback.(type) {
	case nil:
		h.writeByte(0)
	case string:
		h.writeByte(1)
		h.writeString(fallback)
	case *config_parser.Function:
		h.writeByte(2)
		h.writeFunction(fallback)
	case []*config_parser.Function:
		h.writeByte(3)
		h.writeFunctions(fallback)
	default:
		return fmt.Errorf("unsupported function-or-string value type: %T", fallback)
	}
	return nil
}

func hashNormalizedProgram(program *NormalizedProgram) ([sha256.Size]byte, error) {
	if program == nil {
		return [sha256.Size]byte{}, fmt.Errorf("nil normalized routing program")
	}
	hasher := newCanonicalPolicyHasher(normalizedPolicyHashSchema)
	hasher.writeRules(program.Rules)
	if err := hasher.writeFallback(program.Fallback); err != nil {
		return [sha256.Size]byte{}, err
	}
	return hasher.sum(), nil
}

func (h *canonicalPolicyHasher) writeStrings(values []string) {
	h.writeBool(values != nil)
	h.writeUint64(uint64(len(values)))
	for _, value := range values {
		h.writeString(value)
	}
}

func (h *canonicalPolicyHasher) writePrefix(prefix netip.Prefix) {
	address := prefix.Addr()
	h.writeBool(address.IsValid())
	h.writeBool(address.Is4())
	h.writeString(address.Zone())
	switch {
	case address.Is4():
		bytes := address.As4()
		h.writeBytes(bytes[:])
	case address.IsValid():
		bytes := address.As16()
		h.writeBytes(bytes[:])
	default:
		h.writeBytes(nil)
	}
	h.writeInt(prefix.Bits())
}

func (h *canonicalPolicyHasher) writePrefixSets(prefixSets [][]netip.Prefix) {
	h.writeBool(prefixSets != nil)
	h.writeUint64(uint64(len(prefixSets)))
	for _, prefixes := range prefixSets {
		h.writeBool(prefixes != nil)
		h.writeUint64(uint64(len(prefixes)))
		for _, prefix := range prefixes {
			h.writePrefix(prefix)
		}
	}
}

func hashCompiledPolicy(outboundIDs []OutboundID, plan CompiledPolicyPlan) [sha256.Size]byte {
	hasher := newCanonicalPolicyHasher(compiledPolicyHashSchema)
	hasher.writeBool(outboundIDs != nil)
	hasher.writeUint64(uint64(len(outboundIDs)))
	for _, binding := range outboundIDs {
		hasher.writeString(binding.Name)
		hasher.writeUint64(uint64(binding.ID))
	}
	hasher.writeBool(plan.Matches != nil)
	hasher.writeUint64(uint64(len(plan.Matches)))
	for _, match := range plan.Matches {
		hasher.writeUint64(uint64(match.Type))
		hasher.writeBool(match.Not)
		hasher.writeUint64(uint64(match.Outbound))
		hasher.writeUint64(uint64(match.Mark))
		hasher.writeBool(match.Must)
		hasher.writeString(string(match.DomainKey))
		hasher.writeStrings(match.Domains)
		hasher.writeUint64(uint64(match.PrefixSetIndex))
		hasher.writeUint64(uint64(match.PortStart))
		hasher.writeUint64(uint64(match.PortEnd))
		hasher.writeUint64(uint64(match.Mask))
		hasher.writeBytes(match.ProcessName[:])
		hasher.writeUint64(uint64(match.DSCP))
	}
	hasher.writeBool(plan.PredicateGroups != nil)
	hasher.writeUint64(uint64(len(plan.PredicateGroups)))
	for _, group := range plan.PredicateGroups {
		hasher.writeString(group.Name)
		hasher.writeString(group.Key)
		hasher.writeBool(group.Not)
		hasher.writeInt(group.Start)
		hasher.writeInt(group.End)
	}
	hasher.writePrefixSets(plan.PrefixSets)
	hasher.writeInt(plan.DeduplicatedPrefixSetCount)
	hasher.writeStrings(plan.ReferencedOutbounds)
	hasher.writeBool(plan.PacketMetadataSensitive)
	return hasher.sum()
}
