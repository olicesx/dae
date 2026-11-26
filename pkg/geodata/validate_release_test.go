/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org
 */

package geodata

import (
	"bytes"
	"context"
	"net"
	"testing"

	"google.golang.org/protobuf/proto"
)

func bytesReader(payload []byte) *bytes.Reader { return bytes.NewReader(payload) }

func largeGeoIPList(t *testing.T, code string, items int) []byte {
	t.Helper()
	entry := &GeoIP{CountryCode: code}
	for i := 0; i < items; i++ {
		address := make(net.IP, 4)
		address[0], address[1], address[2] = 10, byte(i>>16), byte(i>>8)
		entry.Cidr = append(entry.Cidr, &CIDR{Ip: address, Prefix: 32})
	}
	payload, err := proto.Marshal(&GeoIPList{Entry: []*GeoIP{entry, {CountryCode: "cn", Cidr: []*CIDR{{Ip: net.IPv4(1, 2, 3, 0).To4(), Prefix: 24}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// The default source publishes a category of about 260,000 prefixes. It must
// validate, because the loader that replaces the asset accepts it.
func TestValidateUpdateAcceptsPublishedGeoIPCategorySize(t *testing.T) {
	if err := ValidateUpdate(context.Background(), bytesReader(largeGeoIPList(t, "US", 260_000)), "geoip", []string{"us", "cn"}); err != nil {
		t.Fatalf("ValidateUpdate() = %v, want a published-size category accepted", err)
	}
}

func TestValidateUpdateRejectsCategoryOverItemBound(t *testing.T) {
	if err := ValidateUpdate(context.Background(), bytesReader(largeGeoIPList(t, "US", maxRecordItems+1)), "geoip", nil); err == nil {
		t.Fatal("ValidateUpdate() accepted a category over the item bound")
	}
}
