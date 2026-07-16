/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func newPhase1DNSCacheObservationTestCache(t testing.TB, name string, deadline time.Time) *DnsCache {
	t.Helper()
	cache := &DnsCache{
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   name,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: []byte{203, 0, 113, 1},
			},
		},
		Deadline:         deadline,
		OriginalDeadline: deadline,
	}
	if err := cache.PrepackResponse(name, dnsmessage.TypeA); err != nil {
		t.Fatalf("PrepackResponse() error = %v", err)
	}
	return cache
}

func phase1DNSCacheLatencyTotal(recorder *phase1Observability, outcome phase1DNSCacheOutcome) uint64 {
	var total uint64
	for bucket := phase1LatencyBucket(0); bucket < phase1LatencyBucketCount; bucket++ {
		total += recorder.dnsCacheLatencyCount(outcome, bucket)
	}
	return total
}

func TestPhase1DNSCacheLookupObservations(t *testing.T) {
	recorder := installPhase1ObservabilityForTest(t, 1)
	controller := newTestDnsController()
	query := new(dnsmessage.Msg)
	query.SetQuestion("phase1-cache.example.", dnsmessage.TypeA)

	now := time.Now()
	controller.dnsCache.Store("fresh", newPhase1DNSCacheObservationTestCache(t, "phase1-cache.example.", now.Add(time.Minute)))
	if response, _ := controller.LookupDnsRespCache_(query, "fresh", false); len(response) == 0 {
		t.Fatal("fresh cache lookup returned no response")
	}

	controller.optimisticCacheEnabled.Store(true)
	controller.optimisticCacheTtl.Store(60)
	controller.dnsCache.Store("stale", newPhase1DNSCacheObservationTestCache(t, "phase1-cache.example.", now.Add(-time.Second)))
	if response, _ := controller.LookupDnsRespCache_(query, "stale", false); len(response) == 0 {
		t.Fatal("stale cache lookup returned no response")
	}

	controller.optimisticCacheEnabled.Store(false)
	controller.dnsCache.Store("expired", newPhase1DNSCacheObservationTestCache(t, "phase1-cache.example.", now.Add(-time.Second)))
	if response, _ := controller.LookupDnsRespCache_(query, "expired", false); response != nil {
		t.Fatalf("expired cache lookup response = %x, want nil", response)
	}

	if response, _ := controller.LookupDnsRespCache_(query, "missing", false); response != nil {
		t.Fatalf("missing cache lookup response = %x, want nil", response)
	}

	for outcome, want := range map[phase1DNSCacheOutcome]uint64{
		phase1DNSCacheHit:         1,
		phase1DNSCacheStale:       1,
		phase1DNSCacheUnavailable: 1,
		phase1DNSCacheMiss:        1,
	} {
		if got := recorder.dnsCacheCount(outcome); got != want {
			t.Fatalf("DNS cache outcome %d count = %d, want %d", outcome, got, want)
		}
		if got := phase1DNSCacheLatencyTotal(recorder, outcome); got != want {
			t.Fatalf("DNS cache outcome %d latency samples = %d, want %d", outcome, got, want)
		}
	}
	if got := recorder.dnsCacheCount(phase1DNSCacheFailure); got != 0 {
		t.Fatalf("DNS cache failure count = %d, want 0", got)
	}
}

func TestPhase1DNSCacheLookupObservationSampling(t *testing.T) {
	recorder := installPhase1ObservabilityForTest(t, 2)
	controller := newTestDnsController()
	query := new(dnsmessage.Msg)
	query.SetQuestion("phase1-sampling.example.", dnsmessage.TypeA)

	for range 2 {
		if response, _ := controller.LookupDnsRespCache_(query, "missing", false); response != nil {
			t.Fatalf("missing cache lookup response = %x, want nil", response)
		}
	}

	if got := recorder.dnsCacheCount(phase1DNSCacheMiss); got != 1 {
		t.Fatalf("sampled DNS cache miss count = %d, want 1", got)
	}
	if got := phase1DNSCacheLatencyTotal(recorder, phase1DNSCacheMiss); got != 1 {
		t.Fatalf("sampled DNS cache miss latency samples = %d, want 1", got)
	}
}
