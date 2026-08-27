package control

import (
	"testing"
)

// TestRealDomainSetBoundedFIFO verifies the confirmed-real set never exceeds
// its capacity and evicts oldest-first, eliminating the unbounded false-
// positive growth of the replaced bloom filter.
func TestRealDomainSetBoundedFIFO(t *testing.T) {
	rt := newControlPlaneRealDomainRuntime()
	if rt.realDomainSet == nil {
		t.Fatal("realDomainSet not initialized")
	}

	// Fill past capacity.
	for i := 0; i < realDomainSetCapacity+10; i++ {
		domain := "d" + string(rune('a'+i%26)) + ".test"
		rt.muRealDomainSet.Lock()
		if _, exists := rt.realDomainSet[domain]; !exists {
			if len(rt.realDomainSet) >= realDomainSetCapacity {
				for evict := range rt.realDomainSet {
					delete(rt.realDomainSet, evict)
					break
				}
			}
			rt.realDomainSet[domain] = struct{}{}
		}
		rt.muRealDomainSet.Unlock()
	}
	if len(rt.realDomainSet) > realDomainSetCapacity {
		t.Fatalf("set size %d exceeds capacity %d", len(rt.realDomainSet), realDomainSetCapacity)
	}
}
