/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/daeuniverse/dae/config"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
)

// PolicyEpoch identifies an immutable policy generation.
type PolicyEpoch uint64

// PolicySnapshot is an immutable, generation-scoped routing program.
//
// It deliberately owns only semantic policy data. Runtime resources such as
// BPF maps, listeners, and dialers belong to the control-plane runtime and are
// attached by later refactor phases.
type PolicySnapshot struct {
	epoch   PolicyEpoch
	program *NormalizedProgram
	hash    [sha256.Size]byte
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

	encoded, err := json.Marshal(struct {
		Rules    any `json:"rules"`
		Fallback any `json:"fallback"`
	}{
		Rules:    clonedProgram.Rules,
		Fallback: clonedProgram.Fallback,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal routing policy for hash: %w", err)
	}

	return &PolicySnapshot{
		epoch:   epoch,
		program: clonedProgram,
		hash:    sha256.Sum256(encoded),
	}, nil
}

// Epoch returns the immutable generation identifier.
func (s *PolicySnapshot) Epoch() PolicyEpoch {
	if s == nil {
		return 0
	}
	return s.epoch
}

// Hash returns the semantic content hash without the generation identifier.
func (s *PolicySnapshot) Hash() [sha256.Size]byte {
	if s == nil {
		return [sha256.Size]byte{}
	}
	return s.hash
}

// RuleCount returns the number of normalized routing rules in the snapshot.
func (s *PolicySnapshot) RuleCount() int {
	if s == nil || s.program == nil {
		return 0
	}
	return len(s.program.Rules)
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
