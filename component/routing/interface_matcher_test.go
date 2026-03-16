package routing

import "testing"

func TestParseInterfaceMatchers(t *testing.T) {
	vals, err := parseInterfaceMatchers("wan", []string{"0eth", "0eth", "1eth"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 2 {
		t.Fatalf("unexpected len: %d", len(vals))
	}
	if vals[0].Zone != InterfaceZoneWan || vals[0].Name != "0eth" {
		t.Fatalf("unexpected first value: %+v", vals[0])
	}
}

func TestMatchInterfaceDirectionAndName(t *testing.T) {
	if !MatchInterface(InterfaceMatcher{Zone: InterfaceZoneWan, Name: "0eth"}, InterfaceDirectionOut, "wan.0eth") {
		t.Fatal("wan out should match")
	}
	if MatchInterface(InterfaceMatcher{Zone: InterfaceZoneWan, Name: "0eth"}, InterfaceDirectionIn, "wan.0eth") {
		t.Fatal("wan in should not match")
	}
	if !MatchInterface(InterfaceMatcher{Zone: InterfaceZoneLan, Name: "3eth"}, InterfaceDirectionIn, "lan.3eth") {
		t.Fatal("lan in should match")
	}
	if MatchInterface(InterfaceMatcher{Zone: InterfaceZoneLan, Name: "3eth"}, InterfaceDirectionOut, "lan.3eth") {
		t.Fatal("lan out should not match")
	}
}
