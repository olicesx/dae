/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
)

func newSemanticsController(t *testing.T) *DnsController {
	t.Helper()
	return newCorpusControllerWithDefaultChooser(t, &config.Dns{
		Routing: config.DnsRouting{
			Request:  config.DnsRequestRouting{Fallback: config.FunctionOrString("asis")},
			Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
		},
	})
}

func storedEntry(t *testing.T, c *DnsController, cacheKey string) *DnsCache {
	t.Helper()
	v, ok := c.dnsCache.Load(cacheKey)
	if !ok {
		t.Fatalf("no cache entry for %q", cacheKey)
	}
	entry, ok := v.(*DnsCache)
	if !ok {
		t.Fatalf("cache entry for %q has type %T", cacheKey, v)
	}
	return entry
}

// TestPositiveEntryLifetimeUsesMinimumRecordTtl pins RFC 2181/4035 lifetime
// semantics: a short-lived A following a long-lived CNAME must expire the
// whole entry, not extend the A for the CNAME's lifetime.
func TestPositiveEntryLifetimeUsesMinimumRecordTtl(t *testing.T) {
	c := newSemanticsController(t)
	const cacheKey = "semantics-min-ttl|1.1.1.1"

	msg := dnsAResponseMsg("mixed.example.com.", "198.51.100.10")
	msg.Question[0].Qtype = dnsmessage.TypeCNAME
	msg.Answer = []dnsmessage.RR{
		&dnsmessage.CNAME{
			Hdr: dnsmessage.RR_Header{Name: "mixed.example.com.", Rrtype: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, Ttl: 3600},
			Target: "target.example.com.",
		},
		&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "target.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 30},
			A:   net.ParseIP("198.51.100.10").To4(),
		},
	}
	msg.Response = true
	if err := c.NormalizeAndCacheDnsResp_(msg, cacheKey); err != nil {
		t.Fatalf("NormalizeAndCacheDnsResp_: %v", err)
	}
	entry := storedEntry(t, c, cacheKey)
	remaining := time.Until(entry.Deadline)
	if remaining > 35*time.Second || remaining <= 0 {
		t.Fatalf("entry deadline = %v (remaining %v), want ~30s", entry.Deadline, remaining)
	}
}

// TestNodataNegativeLifetimeUsesSoa pins RFC 2308: NODATA lifetime follows
// min(SOA TTL, SOA.MINIMUM) with a cap; the SOA is retained in the entry.
func TestNodataNegativeLifetimeUsesSoa(t *testing.T) {
	c := newSemanticsController(t)
	const cacheKey = "semantics-nodata|1.1.1.1"

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("empty.example.com.", dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Ns = []dnsmessage.RR{
		&dnsmessage.SOA{
			Hdr: dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, Ttl: 300},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 60,
			Retry:   60,
			Expire:  600,
			Minttl:  10,
		},
	}
	if err := c.NormalizeAndCacheDnsResp_(msg, cacheKey); err != nil {
		t.Fatalf("NormalizeAndCacheDnsResp_: %v", err)
	}
	entry := storedEntry(t, c, cacheKey)
	remaining := time.Until(entry.Deadline)
	if remaining > 15*time.Second || remaining <= 0 {
		t.Fatalf("NODATA deadline = %v (remaining %v), want ~10s (SOA.MINIMUM)", entry.Deadline, remaining)
	}
	if len(entry.NS) == 0 {
		t.Fatal("NODATA entry must retain the SOA in its authority section")
	}
}

// TestUncacheableNegativesAreNotStored pins RFC 2308 §5: no-SOA NODATA,
// NS-only referrals and NXDOMAIN must not create cache entries.
func TestUncacheableNegativesAreNotStored(t *testing.T) {
	c := newSemanticsController(t)

	// NXDOMAIN without SOA handling: never stored (packed cache replays only
	// success responses).
	nx := new(dnsmessage.Msg)
	nx.SetQuestion("gone.example.com.", dnsmessage.TypeA)
	nx.Response = true
	nx.Rcode = dnsmessage.RcodeNameError
	if err := c.NormalizeAndCacheDnsResp_(nx, "semantics-nx"); err != nil {
		t.Fatalf("NormalizeAndCacheDnsResp_(nx): %v", err)
	}
	if _, ok := c.dnsCache.Load("semantics-nx"); ok {
		t.Fatal("NXDOMAIN must not be cached")
	}

	// NODATA without an SOA is not a cacheable negative.
	noSoa := new(dnsmessage.Msg)
	noSoa.SetQuestion("empty-no-soa.example.com.", dnsmessage.TypeA)
	noSoa.Response = true
	if err := c.NormalizeAndCacheDnsResp_(noSoa, "semantics-no-soa"); err != nil {
		t.Fatalf("NormalizeAndCacheDnsResp_(no-soa): %v", err)
	}
	if _, ok := c.dnsCache.Load("semantics-no-soa"); ok {
		t.Fatal("SOA-less NODATA must not be cached")
	}

	// An NS-only authority is a referral, not a negative answer.
	referral := new(dnsmessage.Msg)
	referral.SetQuestion("delegated.example.com.", dnsmessage.TypeA)
	referral.Response = true
	referral.Ns = []dnsmessage.RR{
		&dnsmessage.NS{
			Hdr:  dnsmessage.RR_Header{Name: "example.com.", Rrtype: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, Ttl: 3600},
			Ns:   "ns1.other.example.",
		},
	}
	if err := c.NormalizeAndCacheDnsResp_(referral, "semantics-referral"); err != nil {
		t.Fatalf("NormalizeAndCacheDnsResp_(referral): %v", err)
	}
	if _, ok := c.dnsCache.Load("semantics-referral"); ok {
		t.Fatal("NS-only referral must not be cached as a negative")
	}
}

// TestRefreshNegativeSupersedesExpiredPositive pins RFC 8767 §4: an accepted
// NXDOMAIN from the configured upstream must not leave the disproven expired
// positive in place for the rest of the stale window.
func TestRefreshNegativeSupersedesExpiredPositive(t *testing.T) {
	c := newSemanticsController(t)
	const cacheKey = "semantics-refresh-nx"

	// Plant an expired positive entry exactly as the stale path would leave it.
	expired := &DnsCache{
		Deadline: time.Now().Add(-time.Second),
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: "revoked.example.com.", Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 0},
			A:   net.ParseIP("198.51.100.77").To4(),
		}},
	}
	c.dnsCache.Store(cacheKey, expired)

	c.evictSupersededExpiredPositive(cacheKey)
	if _, ok := c.dnsCache.Load(cacheKey); ok {
		t.Fatal("superseded expired positive must be evicted after an accepted negative refresh")
	}

	// A fresh entry (newer positive stored while the refresh was in flight)
	// must be left untouched.
	fresh := &DnsCache{Deadline: time.Now().Add(time.Hour)}
	c.dnsCache.Store(cacheKey, fresh)
	c.evictSupersededExpiredPositive(cacheKey)
	if _, ok := c.dnsCache.Load(cacheKey); !ok {
		t.Fatal("fresh entry must survive a delayed negative refresh")
	}
}
