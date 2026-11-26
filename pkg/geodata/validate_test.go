/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package geodata

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestValidateUpdate(t *testing.T) {
	cn := &GeoSite{CountryCode: "CN", Domain: []*Domain{{Type: Domain_RootDomain, Value: "example.com"}}}
	payload, err := proto.Marshal(&GeoSiteList{Entry: []*GeoSite{cn}})
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append(bytes.Clone(payload), payload...)
	badTail := append(bytes.Clone(payload), 10, 8, 10, 3, 'x')
	tests := []struct {
		name     string
		kind     string
		data     []byte
		required []string
		valid    bool
	}{
		{"valid", "geosite", payload, []string{"cn"}, true},
		{"missing category", "geosite", payload, []string{"other"}, false},
		{"duplicate category", "geosite", duplicate, nil, false},
		{"malformed trailing entry", "geosite", badTail, []string{"cn"}, false},
		{"malformed unsupported record", "geosite", []byte{10, 3, 10, 1, 255}, nil, false},
		{"incorrect kind", "geoip", payload, nil, false},
		{"declared entry limit", "geosite", []byte{10, 128, 128, 128, 128, 8}, nil, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateUpdate(context.Background(), bytes.NewReader(test.data), test.kind, test.required)
			if (err == nil) != test.valid {
				t.Fatalf("ValidateUpdate() = %v, valid = %v", err, test.valid)
			}
		})
	}
}

func TestValidateUpdateGeoIPPrefix(t *testing.T) {
	for _, prefix := range []uint32{24, 33} {
		payload, err := proto.Marshal(&GeoIPList{Entry: []*GeoIP{{CountryCode: "CN", Cidr: []*CIDR{{Ip: []byte{1, 2, 3, 4}, Prefix: prefix}}}}})
		if err != nil {
			t.Fatal(err)
		}
		err = ValidateUpdate(context.Background(), bytes.NewReader(payload), "geoip", []string{"cn"})
		if (err == nil) != (prefix == 24) {
			t.Fatalf("ValidateUpdate() for prefix %d = %v", prefix, err)
		}
	}
}
