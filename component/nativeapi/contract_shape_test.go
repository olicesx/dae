/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>>
 */

package nativeapi

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// TestExtensionNamespaceIsDerivedFromEngineName pins the one place the engine
// namespace is spelled twice: a struct tag cannot name a constant, so the tag
// of GroupConfig.Extension is checked against EngineExtension. If the two
// drifted apart, the contract's x-<engine> member would vanish and an unknown
// one would appear in its place.
func TestExtensionNamespaceIsDerivedFromEngineName(t *testing.T) {
	if !strings.HasPrefix(EngineExtension, "x-"+EngineName) {
		t.Fatalf("EngineExtension = %q, want x-%s", EngineExtension, EngineName)
	}
	field, ok := reflect.TypeOf(GroupConfig{}).FieldByName("Extension")
	if !ok {
		t.Fatal("GroupConfig has no Extension field")
	}
	name := strings.Split(field.Tag.Get("json"), ",")[0]
	if name != EngineExtension {
		t.Fatalf("GroupConfig.Extension is tagged %q, want the %s member", name, EngineExtension)
	}
	if !strings.HasPrefix(DirectStatsPath, BasePath+"/"+EngineExtension+"/") {
		t.Fatalf("DirectStatsPath = %q, want it under %s/%s", DirectStatsPath, BasePath, EngineExtension)
	}
}

// TestDatapathOmitsDetailItDoesNotHave pins the wire shape of a datapath
// summary. The contract lets ebpf carry attachments and maps or leave both
// out, but a present maps member has to be an object, so a summary must not
// write a null placeholder for the detail it does not have.
func TestDatapathOmitsDetailItDoesNotHave(t *testing.T) {
	summary, err := json.Marshal(Datapath{Ebpf: &EbpfDetail{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{`"maps"`, `"attachments"`} {
		if strings.Contains(string(summary), member) {
			t.Fatalf("a datapath summary carries %s: %s", member, summary)
		}
	}
	detail, err := json.Marshal(Datapath{Ebpf: &EbpfDetail{Maps: &EbpfMaps{State: "unknown"}}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Ebpf struct {
			Maps map[string]any `json:"maps"`
		} `json:"ebpf"`
	}
	if err := json.Unmarshal(detail, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Ebpf.Maps["state"] != "unknown" {
		t.Fatalf("datapath detail maps = %s, want the map state it was given", detail)
	}
	if connState, present := decoded.Ebpf.Maps["conn_state"]; !present || connState != nil {
		t.Fatalf("datapath detail conn_state = %v, want an explicit null: %s", connState, detail)
	}
}

// TestProbesAdvertiseOnlyIpVersions pins what the probes capability lists:
// IP versions. "any" is a value a probe request takes, and listing it here
// made the capability fail the contract's IpVersion enum.
func TestProbesAdvertiseOnlyIpVersions(t *testing.T) {
	server := newTestServer(t, Config{AllowAnonymousLoopback: true}, fakeRuntimeProvider{runtime: testRuntime()})
	server.SetProbeProvider(fakeProbes{})

	response := doRequest(server, http.MethodGet, "/api/v1/capabilities", "127.0.0.1:1234", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	resources := decodeJSON(t, response)["resources"].(map[string]any)
	versions, _ := resources["probes"].(map[string]any)["ip_versions"].([]any)
	if len(versions) != 2 || versions[0] != "ipv4" || versions[1] != "ipv6" {
		t.Fatalf("probes.ip_versions = %v, want [ipv4 ipv6]", versions)
	}
}
