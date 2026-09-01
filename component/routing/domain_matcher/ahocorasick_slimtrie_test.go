/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
)

func TestAhocorasickSlimtrie(t *testing.T) {

	logrus.SetLevel(logrus.TraceLevel)
	simulatedDomainSet, err := getDomain()
	if err != nil {
		if strings.Contains(err.Error(), "geosite.dat: file does not exist") {
			t.Skipf("skip due to missing geosite.dat in test environment: %v", err)
		}
		t.Fatal(err)
	}
	// The Bruteforce reference matcher was removed as dead code; this test now
	// exercises the trie as a smoke test (Add/Build/Match must not panic) over
	// the same geosite-derived sample corpus.
	actrie := NewAhocorasickSlimtrie(logrus.StandardLogger(), consts.MaxMatchSetLen)
	for _, domains := range simulatedDomainSet {
		actrie.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = actrie.Build(); err != nil {
		t.Fatal(err)
	}

	r := rand.New(rand.NewSource(200))
	for range 10000 {
		sample := TestSample[r.Intn(len(TestSample))]
		choice := r.Intn(10)
		switch {
		case choice < 4:
			addN := r.Intn(5)
			buf := make([]byte, addN)
			for i := range buf {
				buf[i] = 'a' + byte(r.Intn('z'-'a'))
			}
			sample = string(buf) + "." + sample
		case choice >= 4 && choice < 6:
			k := r.Intn(len(sample))
			sample = sample[k:]
		default:
		}
		_ = actrie.MatchDomainBitmap(sample)
	}
}

func TestAddSetRejectsOutOfBoundsBitIndex(t *testing.T) {
	// An index equal to bitLength used to panic on the toBuildTrie write;
	// it must surface as a Build error instead.
	actrie := NewAhocorasickSlimtrie(logrus.StandardLogger(), 8)
	actrie.AddSet(8, []string{"example.com"}, consts.RoutingDomainKey_Full)
	if err := actrie.Build(); err == nil {
		t.Fatal("Build() error = nil, want out-of-range error for bitIndex == bitLength")
	}

	negative := NewAhocorasickSlimtrie(logrus.StandardLogger(), 8)
	negative.AddSet(-1, []string{"example.com"}, consts.RoutingDomainKey_Suffix)
	if err := negative.Build(); err == nil {
		t.Fatal("Build() error = nil, want out-of-range error for negative bitIndex")
	}
}

func TestMatchDomainBitmapHitReturnsSharedAlias(t *testing.T) {
	actrie := NewAhocorasickSlimtrie(logrus.StandardLogger(), 32)
	actrie.AddSet(0, []string{"example.com"}, consts.RoutingDomainKey_Full)
	if err := actrie.Build(); err != nil {
		t.Fatal(err)
	}
	first := actrie.MatchDomainBitmap("example.com")
	second := actrie.MatchDomainBitmap("example.com")
	if len(first) == 0 || first[0] == 0 {
		t.Fatal("expected a hit bit")
	}
	if &first[0] != &second[0] {
		t.Fatal("hit path cloned the memoized bitmap; callers must treat it as immutable")
	}
}
