/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func testDialerIndexEndpoint(d *dialer.Dialer) *UdpEndpoint {
	return &UdpEndpoint{
		Dialer: d,
		endpointNetworkType: dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_4,
		},
	}
}

// dialerBucketContains reports whether ue is in the bucket indexed under key.
func dialerBucketContains(pool *UdpEndpointPool, key udpEndpointDialerNetworkKey, ue *UdpEndpoint) bool {
	actual, ok := pool.dialerIndex.Load(key)
	if !ok {
		return false
	}
	bucket := actual.(*udpEndpointDialerBucket)
	bucket.mu.RLock()
	defer bucket.mu.RUnlock()
	_, registered := bucket.endpoints[ue]
	return registered
}

// TestUnregisterEndpointDropsEmptyDialerBucket pins the release half of the
// dialer index: the key embeds *dialer.Dialer, so an empty bucket left behind
// pins one generation's dialer (collections, proxy cache, HTTP clients) after
// every seamless reload.
func TestUnregisterEndpointDropsEmptyDialerBucket(t *testing.T) {
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)

	d := &dialer.Dialer{}
	ue := testDialerIndexEndpoint(d)
	key, ok := pool.endpointDialerNetworkKey(ue)
	if !ok {
		t.Fatal("expected a dialer index key")
	}

	pool.registerEndpoint(ue)
	if !dialerBucketContains(pool, key, ue) {
		t.Fatal("a registered endpoint must be in the bucket indexed under its key")
	}

	pool.unregisterEndpoint(ue)
	if _, ok := pool.dialerIndex.Load(key); ok {
		t.Fatal("the last unregister must drop the now empty dialer bucket")
	}
}

// TestDialerBucketOutlivesOneOfItsEndpoints covers the shared case: endpoints
// of one dialer and network type share a bucket, which stays indexed while any
// of them is registered.
func TestDialerBucketOutlivesOneOfItsEndpoints(t *testing.T) {
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)

	d := &dialer.Dialer{}
	first := testDialerIndexEndpoint(d)
	second := testDialerIndexEndpoint(d)
	key, ok := pool.endpointDialerNetworkKey(first)
	if !ok {
		t.Fatal("expected a dialer index key")
	}

	pool.registerEndpoint(first)
	pool.registerEndpoint(second)
	bucket, _ := pool.dialerIndex.Load(key)

	pool.unregisterEndpoint(first)
	if current, ok := pool.dialerIndex.Load(key); !ok || current != bucket {
		t.Fatal("a bucket that still has a registered endpoint must stay indexed")
	}
	if !dialerBucketContains(pool, key, second) {
		t.Fatal("unregistering one endpoint must not drop its sibling")
	}

	pool.unregisterEndpoint(second)
	if _, ok := pool.dialerIndex.Load(key); ok {
		t.Fatal("the bucket must go with its last endpoint")
	}
}

// TestRegisterEndpointKeepsDialerIndexConsistent races register against
// unregister and dialer retirement. registerEndpoint returns only with the
// endpoint in the bucket indexed under its key: joining a bucket that an
// unregister just emptied would make the endpoint invisible to dialer
// invalidation, which is the race the old "keep empty buckets" rule avoided
// by never releasing them.
func TestRegisterEndpointKeepsDialerIndexConsistent(t *testing.T) {
	pool := NewUdpEndpointPool()
	t.Cleanup(pool.Close)

	d := &dialer.Dialer{}
	endpoints := []*UdpEndpoint{testDialerIndexEndpoint(d), testDialerIndexEndpoint(d)}
	key, ok := pool.endpointDialerNetworkKey(endpoints[0])
	if !ok {
		t.Fatal("expected a dialer index key")
	}

	var wg sync.WaitGroup
	for _, ue := range endpoints {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 2000 {
				pool.registerEndpoint(ue)
				if !dialerBucketContains(pool, key, ue) {
					t.Errorf("registered endpoint is not in the bucket indexed under its key")
					return
				}
				pool.unregisterEndpoint(ue)
			}
		}()
		go func() {
			defer wg.Done()
			for range 2000 {
				pool.forgetDialerEpochs([]*dialer.Dialer{d})
			}
		}()
	}
	wg.Wait()

	if _, ok := pool.dialerIndex.Load(key); ok {
		t.Fatal("no dialer bucket may outlive its last endpoint")
	}
}
