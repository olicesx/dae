package control

import (
	"context"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func TestResolveForSingleflightRechecksCache(t *testing.T) {
	controller := newTestDnsController()
	query := new(dnsmessage.Msg)
	query.SetQuestion("example.com.", dnsmessage.TypeA)
	query.Id = 0x4321

	cache := &DnsCache{
		Answer: []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		}},
		Deadline: time.Now().Add(time.Minute),
	}
	if err := cache.PrepackResponse("example.com.", dnsmessage.TypeA); err != nil {
		t.Fatalf("PrepackResponse() error = %v", err)
	}
	const cacheKey = "singleflight-cache-key"
	controller.dnsCache.Store(cacheKey, cache)

	result, err := controller.resolveForSingleflightSnapshot(
		context.Background(),
		query,
		DnsRequestSnapshot{},
		0,
		nil,
		cacheKey,
	)
	if err != nil {
		t.Fatalf("resolveForSingleflight() error = %v", err)
	}
	if result == nil || result.Response == nil {
		t.Fatal("resolveForSingleflightSnapshot() returned no DNS response")
	}
	if result.Response.Id != query.Id {
		t.Fatalf("response ID = %d, want %d", result.Response.Id, query.Id)
	}
	if len(result.Response.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(result.Response.Answer))
	}
}

func TestDnsController_NewWorkContext_HonorsLifecycleContext(t *testing.T) {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	ctrl := setTestDnsControllerRuntime(&DnsController{}, func(rt *dnsControllerRuntimeState) {
		rt.lifecycleCtx = lifecycleCtx
	})

	workCtx, workCancel := ctrl.newWorkContext(time.Second)
	defer workCancel()

	select {
	case <-workCtx.Done():
		t.Fatal("work context should stay alive while lifecycle is active")
	default:
	}

	lifecycleCancel()

	select {
	case <-workCtx.Done():
		if workCtx.Err() != context.Canceled {
			t.Fatalf("work context err = %v, want context.Canceled", workCtx.Err())
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for work context to honor lifecycle cancellation")
	}
}
