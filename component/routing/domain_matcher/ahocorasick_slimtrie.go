/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/ahocorasick-domain"
)

var ValidDomainChars = trie.NewValidChars([]byte("0123456789abcdefghijklmnopqrstuvwxyz-.^_"))

type AhocorasickSlimtrie struct {
	log *logrus.Logger

	validAcIndexes     []int
	validTrieIndexes   []int
	validRegexpIndexes []int
	ac                 []*ahocorasick.Matcher
	trie               []*trie.Trie
	regexp             [][]*regexp.Regexp

	toBuildAc   [][][]byte
	toBuildTrie [][]string
	err         error

	// matchCache memoizes the most recent qname resolutions. A single DNS
	// query otherwise recomputes the same domain bitmap up to six times
	// (request select, response select, and once per ip-version x protocol
	// dialer iteration). Capacity-bounded, scan on overflow.
	matchMu       sync.Mutex
	matchCache    map[string][]uint32
	matchCacheOrd []string
}

func NewAhocorasickSlimtrie(log *logrus.Logger, bitLength int) *AhocorasickSlimtrie {
	return &AhocorasickSlimtrie{
		log:         log,
		ac:          make([]*ahocorasick.Matcher, bitLength),
		trie:        make([]*trie.Trie, bitLength),
		regexp:      make([][]*regexp.Regexp, bitLength),
		toBuildAc:   make([][][]byte, bitLength),
		toBuildTrie: make([][]string, bitLength),
	}
}
func (n *AhocorasickSlimtrie) AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey) {
	if n.err != nil {
		return
	}
	// Pre-grow slices to avoid repeated growslice when appending many patterns.
	maxTrieEntries := 0
	maxAcEntries := 0
	switch typ {
	case consts.RoutingDomainKey_Full:
		maxTrieEntries = len(patterns)
	case consts.RoutingDomainKey_Suffix:
		maxTrieEntries = len(patterns) * 2
	case consts.RoutingDomainKey_Keyword:
		maxAcEntries = len(patterns)
	}
	if maxTrieEntries > 0 {
		n.toBuildTrie[bitIndex] = slices.Grow(n.toBuildTrie[bitIndex], maxTrieEntries)
	}
	if maxAcEntries > 0 {
		n.toBuildAc[bitIndex] = slices.Grow(n.toBuildAc[bitIndex], maxAcEntries)
	}
nextPattern:
	for _, d := range patterns {
		switch typ {
		case consts.RoutingDomainKey_Full:
			for _, r := range []byte(d) {
				if !ValidDomainChars.IsValidChar(r) {
					n.log.Warnf("DomainMatcher: skip bad full domain: %v: unexpected char: %v", d, string(r))
					continue nextPattern
				}
			}
			n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "^"+d+"$")
		case consts.RoutingDomainKey_Suffix:
			for _, r := range []byte(d) {
				if !ValidDomainChars.IsValidChar(r) {
					n.log.Warnf("DomainMatcher: skip bad suffix domain: %v: unexpected char: %v", d, string(r))
					continue nextPattern
				}
			}
			if strings.HasPrefix(d, ".") {
				// abc.example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], d+"$")
				// cannot match example.com
			} else {
				// xxx.example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "."+d+"$")
				// example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "^"+d+"$")
				// cannot match abcexample.com
			}
		case consts.RoutingDomainKey_Keyword:
			// Only use ac automaton for "keyword" matching to save memory.
			n.toBuildAc[bitIndex] = append(n.toBuildAc[bitIndex], []byte(d))
		case consts.RoutingDomainKey_Regex:
			r, err := regexp.Compile(d)
			if err != nil {
				n.err = fmt.Errorf("failed to compile regex: %v", d)
				return
			}
			n.regexp[bitIndex] = append(n.regexp[bitIndex], r)
		default:
			n.err = fmt.Errorf("unknown RoutingDomainKey: %v", typ)
			return
		}
	}
}

// matchCacheCap bounds the per-matcher qname->bitmap memo (small: sequential
// DNS traffic has high temporal locality).
const matchCacheCap = 512

func (n *AhocorasickSlimtrie) MatchDomainBitmap(domain string) (bitmap []uint32) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	n.matchMu.Lock()
	if n.matchCache != nil {
		if cached, ok := n.matchCache[domain]; ok {
			n.matchMu.Unlock()
			return cached
		}
	}
	n.matchMu.Unlock()
	bitmap = n.matchDomainBitmapUncached(domain)
	n.matchMu.Lock()
	if n.matchCache == nil {
		n.matchCache = make(map[string][]uint32, 64)
	}
	if _, exists := n.matchCache[domain]; !exists {
		if len(n.matchCacheOrd) >= matchCacheCap {
			evict := n.matchCacheOrd[0]
			n.matchCacheOrd = n.matchCacheOrd[1:]
			delete(n.matchCache, evict)
		}
		n.matchCache[domain] = bitmap
		n.matchCacheOrd = append(n.matchCacheOrd, domain)
	}
	n.matchMu.Unlock()
	return bitmap
}

func (n *AhocorasickSlimtrie) matchDomainBitmapUncached(domain string) (bitmap []uint32) {
	N := len(n.ac) / 32
	if len(n.ac)%32 != 0 {
		N++
	}
	bitmap = make([]uint32, N)
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	// Domain should consist of 'a'-'z' and '.' and '-'
	// NOTE: DO NOT VERIFY THE DOMAIN TO MATCH: https://github.com/daeuniverse/dae/issues/528
	// for _, b := range []byte(domain) {
	// 	if !ahocorasick.IsValidChar(b) {
	// 		return bitmap
	// 	}
	// }
	// Suffix matching.
	suffixTrieDomain := ToSuffixTrieString("^" + domain)
	for _, i := range n.validTrieIndexes {
		if bitmap[i/32]&(1<<(i%32)) > 0 {
			// Already matched.
			continue
		}
		if n.trie[i].HasPrefix(suffixTrieDomain) {
			bitmap[i/32] |= 1 << (i % 32)
		}
	}
	// Keyword matching.
	// Add magic chars as head and tail.
	acDomain := "^" + domain + "$"
	for _, i := range n.validAcIndexes {
		if bitmap[i/32]&(1<<(i%32)) > 0 {
			// Already matched.
			continue
		}
		if n.ac[i].Contains([]byte(acDomain)) {
			bitmap[i/32] |= 1 << (i % 32)
		}
	}
	// Regex matching.
	for _, i := range n.validRegexpIndexes {
		if bitmap[i/32]&(1<<(i%32)) > 0 {
			// Already matched.
			continue
		}
		for _, r := range n.regexp[i] {
			if r.MatchString(domain) {
				bitmap[i/32] |= 1 << (i % 32)
				break
			}
		}
	}
	return bitmap
}
func ToSuffixTrieString(s string) string {
	// No need for end char "$".
	b := []byte(strings.TrimSuffix(s, "$"))
	// Reverse.
	half := len(b) / 2
	for i := range half {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	return string(b)
}
func ToSuffixTrieStrings(s []string) []string {
	to := make([]string, len(s))
	for i := range s {
		to[i] = ToSuffixTrieString(s[i])
	}
	return to
}
func (n *AhocorasickSlimtrie) Build() (err error) {
	n.matchMu.Lock()
	n.matchCache = nil
	n.matchCacheOrd = nil
	n.matchMu.Unlock()

	if n.err != nil {
		return n.err
	}
	n.validAcIndexes = make([]int, 0, len(n.toBuildAc)/8)
	n.validTrieIndexes = make([]int, 0, len(n.toBuildAc)/8)
	n.validRegexpIndexes = make([]int, 0, len(n.toBuildAc)/8)

	// Build AC automaton and trie in parallel for better performance.
	// Use limited concurrency to avoid overwhelming the system.
	numWorkers := min(
		runtime.GOMAXPROCS(0),
		4, // Limit to 4 workers to balance performance and memory
	)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var buildErr error

	// Build AC automaton in parallel.
	wg.Go(func() {
		sem := make(chan struct{}, numWorkers)
		var innerWg sync.WaitGroup
		for i, toBuild := range n.toBuildAc {
			if len(toBuild) == 0 {
				continue
			}
			innerWg.Add(1)
			sem <- struct{}{}
			go func(idx int, patterns [][]byte) {
				defer func() { <-sem }()
				defer innerWg.Done()
				matcher, err := ahocorasick.NewMatcher(patterns)
				if err != nil {
					mu.Lock()
					if buildErr == nil {
						buildErr = err
					}
					mu.Unlock()
					return
				}
				mu.Lock()
				n.ac[idx] = matcher
				n.validAcIndexes = append(n.validAcIndexes, idx)
				mu.Unlock()
			}(i, toBuild)
		}
		innerWg.Wait()
	})

	// Build succinct trie in parallel.
	wg.Go(func() {
		sem := make(chan struct{}, numWorkers)
		var innerWg sync.WaitGroup
		for i, toBuild := range n.toBuildTrie {
			if len(toBuild) == 0 {
				continue
			}
			innerWg.Add(1)
			sem <- struct{}{}
			go func(idx int, patterns []string) {
				defer func() { <-sem }()
				defer innerWg.Done()
				transformed := ToSuffixTrieStrings(patterns)
				t, err := trie.NewTrie(transformed, ValidDomainChars)
				if err != nil {
					mu.Lock()
					if buildErr == nil {
						buildErr = err
					}
					mu.Unlock()
					return
				}
				mu.Lock()
				n.trie[idx] = t
				n.validTrieIndexes = append(n.validTrieIndexes, idx)
				mu.Unlock()
			}(i, toBuild)
		}
		innerWg.Wait()
	})

	wg.Wait()

	if buildErr != nil {
		return buildErr
	}

	// Regexp - already compiled during AddSet, just collect indexes.
	for i := range n.regexp {
		if len(n.regexp[i]) == 0 {
			continue
		}
		n.validRegexpIndexes = append(n.validRegexpIndexes, i)
	}

	// Release unused data.
	n.toBuildAc = nil
	n.toBuildTrie = nil

	// Reclaim temporary build allocations (BFS queues, transformed string
	// slices) immediately so peak memory does not linger into steady state.
	runtime.GC()
	return nil
}
