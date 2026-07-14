/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// This file holds the Phase 0 DNS corpus fixtures. Each fixture focuses on
// one observable behaviour the refactor must preserve. Fixtures are pure
// data + factory functions; the driver lives in refactor_dns_corpus.go.

// udpCacheMissFixture pins the cold-cache UDP path: a fresh query that
// misses cache, contacts the upstream via the forwarder factory, and
// returns the canned answer. The canned answer IP encodes the dial target
// so the assertion catches any drift in dial-arg construction.
func udpCacheMissFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "udp_cache_miss",
		Description: "Cold cache: UDP query misses cache, forwards upstream, returns canned answer",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "asis"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsAResponseMsg("cache-miss.test.", dialArg.bestTarget.Addr().String()), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "cold_query_forwards_and_returns_dialtarget_ip",
				Query: func() *dnsmessage.Msg {
					msg := new(dnsmessage.Msg)
					msg.SetQuestion("cache-miss.test.", dnsmessage.TypeA)
					return msg
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    1,
					AnswerIPv4:     "1.1.1.1", // matches defaultUdpRequest realDst
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					if got := forwardCalls.Load(); got != 1 {
						t.Fatalf("upstream forward calls = %d, want 1", got)
					}
				},
			},
		},
	}
}

// rejectBeforeCacheFixture pins the routing-level reject short-circuit. Even
// when a warm cache entry exists, a Reject routing rule MUST bypass cache and
// return an empty-answer response. This guards the doc comment in
// HandleWithResponseWriter_: "This ensures Reject rules are always applied,
// even if cache exists."
func rejectBeforeCacheFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "reject_before_cache",
		Description: "Routing reject short-circuits even when a warm cache entry exists",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request: config.DnsRequestRouting{
						Rules: []*config_parser.RoutingRule{{
							AndFunctions: []*config_parser.Function{{
								Name: consts.Function_QName,
								Params: []*config_parser.Param{{
									Key: string(consts.RoutingDomainKey_Full),
									Val: "reject.test",
								}},
							}},
							Outbound: config_parser.Function{Name: "reject"},
						}},
						Fallback: "asis",
					},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsAResponseMsg("reject.test.", "9.9.9.9"), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "reject_domain_returns_empty_answer_without_forward",
				PreState: func(t *testing.T, ctrl *DnsController) {
					// Warm the cache with a value that the legacy code would
					// return if reject did not short-circuit. If the refactor
					// ever serves this cached answer, the test catches it.
					key := ctrl.cacheKey("reject.test.", dnsmessage.TypeA)
					if err := ctrl.UpdateDnsCacheTtlWithKey(
						key, "reject.test.", dnsmessage.TypeA,
						dnsAResponseMsg("reject.test.", "9.9.9.9").Answer,
						nil, nil, 60,
					); err != nil {
						t.Fatalf("UpdateDnsCacheTtlWithKey error = %v", err)
					}
				},
				Query: func() *dnsmessage.Msg {
					msg := new(dnsmessage.Msg)
					msg.SetQuestion("reject.test.", dnsmessage.TypeA)
					return msg
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    0,
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					if got := forwardCalls.Load(); got != 0 {
						t.Fatalf("upstream forward calls = %d, want 0", got)
					}
				},
			},
		},
	}
}

// udpCacheHitFixture pins the warm-cache UDP path: a query whose cache key is
// already populated returns immediately without invoking the forwarder. The
// canned warm-cache IP differs from anything the forwarder would return so a
// regression that bypasses cache is observable.
func udpCacheHitFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "udp_cache_hit",
		Description: "Warm cache: cached answer is served without contacting upstream",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "asis"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsAResponseMsg("cache-hit.test.", "203.0.113.99"), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "warm_cache_returns_cached_ip",
				PreState: func(t *testing.T, ctrl *DnsController) {
					req := defaultUdpRequest()
					baseKey := ctrl.cacheKey("cache-hit.test.", dnsmessage.TypeA)
					cacheKey := ctrl.responseCacheKey(
						baseKey, req,
						consts.DnsRequestOutboundIndex_AsIs, nil,
					)
					if err := ctrl.UpdateDnsCacheTtlWithKey(
						cacheKey, "cache-hit.test.", dnsmessage.TypeA,
						dnsAResponseMsg("cache-hit.test.", "203.0.113.42").Answer,
						nil, nil, 60,
					); err != nil {
						t.Fatalf("UpdateDnsCacheTtlWithKey error = %v", err)
					}
				},
				Query: func() *dnsmessage.Msg {
					msg := new(dnsmessage.Msg)
					msg.SetQuestion("cache-hit.test.", dnsmessage.TypeA)
					return msg
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    1,
					AnswerIPv4:     "203.0.113.42", // the cached IP, not the factory IP
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					if got := forwardCalls.Load(); got != 0 {
						t.Fatalf("upstream forward calls = %d, want 0", got)
					}
				},
			},
		},
	}
}

// udpCacheStaleOptimisticFixture pins the optimistic-refresh path: when a
// cached entry is past its freshness window but still within its TTL cap,
// the controller serves the stale answer synchronously while triggering a
// background refresh. The observable contract is: caller sees the stale IP
// immediately and does not wait for refresh.
func udpCacheStaleOptimisticFixture() DnsCorpusFixture {
	var forwardCalls atomic.Int32
	return DnsCorpusFixture{
		Name:        "udp_cache_stale_optimistic",
		Description: "Stale-but-not-expired cache serves stale IP immediately; background refresh is async",
		BuildConfig: func() *config.Dns {
			return &config.Dns{
				Routing: config.DnsRouting{
					Request:  config.DnsRequestRouting{Fallback: "asis"},
					Response: config.DnsResponseRouting{Fallback: "accept"},
				},
			}
		},
		ForwarderFactory: func(upstream *componentdns.Upstream, dialArg dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
			return &stubDnsForwarder{forward: func(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
				forwardCalls.Add(1)
				return dnsAResponseMsg("stale.test.", "203.0.113.240"), nil
			}}, nil
		},
		Cases: []DnsCorpusCase{
			{
				Name: "stale_entry_serves_old_ip",
				PreState: func(t *testing.T, ctrl *DnsController) {
					req := defaultUdpRequest()
					baseKey := ctrl.cacheKey("stale.test.", dnsmessage.TypeA)
					cacheKey := ctrl.responseCacheKey(
						baseKey, req,
						consts.DnsRequestOutboundIndex_AsIs, nil,
					)
					if err := ctrl.UpdateDnsCacheTtlWithKey(
						cacheKey, "stale.test.", dnsmessage.TypeA,
						dnsAResponseMsg("stale.test.", "203.0.113.7").Answer,
						nil, nil, 60,
					); err != nil {
						t.Fatalf("UpdateDnsCacheTtlWithKey error = %v", err)
					}
					cacheValue, ok := ctrl.dnsCache.Load(cacheKey)
					if !ok {
						t.Fatal("stale cache entry was not stored")
					}
					cache := cacheValue.(*DnsCache)
					expiredAt := time.Now().Add(-time.Second)
					cache.Deadline = expiredAt
					cache.deadlineNano.Store(expiredAt.UnixNano())
				},
				Query: func() *dnsmessage.Msg {
					msg := new(dnsmessage.Msg)
					msg.SetQuestion("stale.test.", dnsmessage.TypeA)
					return msg
				},
				Expected: DnsCorpusExpected{
					HasRcode:       true,
					Rcode:          dnsmessage.RcodeSuccess,
					HasAnswerCount: true,
					AnswerCount:    1,
					AnswerIPv4:     "203.0.113.7", // cached (possibly stale) IP
				},
				PostAssert: func(t *testing.T, _ *DnsController, _ *dnsmessage.Msg) {
					deadline := time.Now().Add(time.Second)
					for forwardCalls.Load() == 0 && time.Now().Before(deadline) {
						time.Sleep(10 * time.Millisecond)
					}
					if got := forwardCalls.Load(); got != 1 {
						t.Fatalf("background refresh forward calls = %d, want 1", got)
					}
				},
			},
		},
	}
}
