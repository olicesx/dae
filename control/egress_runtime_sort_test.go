/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// Two subscriptions can carry the same share link, which yields two dialers
// with one node identity. The ordering key must still separate them so the
// merged node always keeps the same representative metadata.
func TestDialerSortKeyDistinguishesDuplicateLinks(t *testing.T) {
	option := &dialer.GlobalOption{Log: logrus.New(), CheckInterval: 15 * time.Second}
	newDialer := func(tag string) *dialer.Dialer {
		return dialer.NewDialerContext(context.Background(), noopAdmissionDialer{}, option,
			dialer.InstanceOption{DisableCheck: true},
			&dialer.Property{Property: D.Property{Name: "a", Link: "ss://same"}, SubscriptionTag: tag})
	}
	first := newDialer("sub_a")
	second := newDialer("sub_b")
	require.NotEqual(t, dialerSortKey(first), dialerSortKey(second))

	// Two providers can carry the same link and subscription tag. ProviderTag
	// must break the tie or the merged node's representative provider drifts
	// with map iteration order.
	sameTag := func(provider string) *dialer.Dialer {
		return dialer.NewDialerContext(context.Background(), noopAdmissionDialer{}, option,
			dialer.InstanceOption{DisableCheck: true},
			&dialer.Property{Property: D.Property{Name: "a", Link: "ss://same"}, SubscriptionTag: "sub", ProviderTag: provider})
	}
	require.NotEqual(t, dialerSortKey(sameTag("p_a")), dialerSortKey(sameTag("p_b")))

	// Identical properties still produce the same key, which is harmless:
	// they are the same node with the same metadata.
	require.Equal(t, dialerSortKey(first), dialerSortKey(newDialer("sub_a")))
}

func TestEgressDialersKeepJoinedKeyOrder(t *testing.T) {
	option := &dialer.GlobalOption{Log: logrus.New(), CheckInterval: 15 * time.Second}
	newDialer := func(property *dialer.Property) *dialer.Dialer {
		d := dialer.NewDialerContext(t.Context(), noopAdmissionDialer{}, option,
			dialer.InstanceOption{DisableCheck: true}, property)
		t.Cleanup(func() { _ = d.Close() })
		return d
	}
	withoutProperty := &dialer.Dialer{}
	prefix := newDialer(&dialer.Property{Property: D.Property{Name: "a", Link: "z"}})
	embeddedNUL := newDialer(&dialer.Property{Property: D.Property{Name: "a\x00b", Link: "z"}})
	subscription := newDialer(&dialer.Property{Property: D.Property{Name: "a", Link: "z"}, SubscriptionTag: "tag"})
	otherProvider := newDialer(&dialer.Property{Property: D.Property{Name: "a", Link: "z"}, SubscriptionTag: "tag", ProviderTag: "other"})
	runtime := newEgressRuntime(option.Log, nil)
	runtime.configureResources(nil, []*dialer.Dialer{prefix, subscription, withoutProperty, otherProvider, embeddedNUL}, nil)
	// The embedded NUL puts "b" next to the other keys' link bytes.
	want := []*dialer.Dialer{withoutProperty, embeddedNUL, prefix, subscription, otherProvider}
	for range 16 {
		require.Equal(t, want, runtime.dialers())
	}
}
