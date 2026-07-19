/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"crypto/sha256"
	"fmt"

	"github.com/daeuniverse/dae/config"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
)

// PolicyEpoch identifies an immutable policy generation.
type PolicyEpoch uint64

// PolicyIdentity is the compact, immutable identity of one normalized policy.
// It can outlive the policy program without retaining the program's rule tree.
type PolicyIdentity struct {
	epoch     PolicyEpoch
	hash      [sha256.Size]byte
	ruleCount int
}

// NewPolicyIdentity calculates a generation identity without retaining program.
func NewPolicyIdentity(epoch PolicyEpoch, program *NormalizedProgram) (PolicyIdentity, error) {
	if program == nil {
		return PolicyIdentity{}, fmt.Errorf("nil normalized routing program")
	}

	policyHash, err := hashNormalizedProgram(program)
	if err != nil {
		return PolicyIdentity{}, fmt.Errorf("hash normalized routing policy: %w", err)
	}

	return PolicyIdentity{
		epoch:     epoch,
		hash:      policyHash,
		ruleCount: len(program.Rules),
	}, nil
}

// Epoch returns the immutable generation identifier.
func (i PolicyIdentity) Epoch() PolicyEpoch {
	return i.epoch
}

// Hash returns the semantic content hash without the generation identifier.
func (i PolicyIdentity) Hash() [sha256.Size]byte {
	return i.hash
}

// RuleCount returns the number of normalized routing rules in the identity.
func (i PolicyIdentity) RuleCount() int {
	return i.ruleCount
}

// PolicySnapshot is an immutable, generation-scoped routing program.
//
// It deliberately owns only semantic policy data. Runtime resources such as
// BPF maps, listeners, and dialers belong to the control-plane runtime and are
// attached by later refactor phases.
type PolicySnapshot struct {
	identity PolicyIdentity
	program  *NormalizedProgram
}

// NewPolicySnapshot creates an immutable snapshot from a normalized program.
func NewPolicySnapshot(epoch PolicyEpoch, program *NormalizedProgram) (*PolicySnapshot, error) {
	if program == nil {
		return nil, fmt.Errorf("nil normalized routing program")
	}

	clonedProgram, err := NewNormalizedProgram(program.Rules, cloneFunctionOrString(program.Fallback))
	if err != nil {
		return nil, fmt.Errorf("clone normalized routing program: %w", err)
	}
	return NewPolicySnapshotFromOwnedProgram(epoch, clonedProgram)
}

// NewPolicySnapshotFromOwnedProgram creates a snapshot without cloning program.
// The caller transfers mutation ownership and may only read program afterwards.
func NewPolicySnapshotFromOwnedProgram(epoch PolicyEpoch, program *NormalizedProgram) (*PolicySnapshot, error) {
	identity, err := NewPolicyIdentity(epoch, program)
	if err != nil {
		return nil, err
	}

	return &PolicySnapshot{
		identity: identity,
		program:  program,
	}, nil
}

// Identity returns a compact identity that does not retain the policy program.
func (s *PolicySnapshot) Identity() PolicyIdentity {
	if s == nil {
		return PolicyIdentity{}
	}
	return s.identity
}

// Epoch returns the immutable generation identifier.
func (s *PolicySnapshot) Epoch() PolicyEpoch {
	return s.Identity().Epoch()
}

// Hash returns the semantic content hash without the generation identifier.
func (s *PolicySnapshot) Hash() [sha256.Size]byte {
	return s.Identity().Hash()
}

// RuleCount returns the number of normalized routing rules in the snapshot.
func (s *PolicySnapshot) RuleCount() int {
	return s.Identity().RuleCount()
}

// CloneProgram returns an independent normalized program for a compiler.
// Mutating the returned value cannot mutate the policy snapshot.
func (s *PolicySnapshot) CloneProgram() (*NormalizedProgram, error) {
	if s == nil || s.program == nil {
		return nil, fmt.Errorf("nil policy snapshot")
	}
	return NewNormalizedProgram(s.program.Rules, cloneFunctionOrString(s.program.Fallback))
}

// Lower invokes the legacy lowering contract against an isolated program copy.
func (s *PolicySnapshot) Lower(
	log *logrus.Logger,
	registerParsers func(*RulesBuilder),
	addFallback func(config.FunctionOrString) error,
) error {
	program, err := s.CloneProgram()
	if err != nil {
		return err
	}
	return program.Lower(log, registerParsers, addFallback)
}

func cloneFunctionOrString(value config.FunctionOrString) config.FunctionOrString {
	if value == nil {
		return nil
	}
	return deepcopy.Copy(value)
}
