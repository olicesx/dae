package common

import (
	"strings"
	"testing"
)

func TestEffectiveSoMarkFromDaeDefaultsToInternalMark(t *testing.T) {
	if got := EffectiveSoMarkFromDae(0); got != InternalSoMarkFromDae {
		t.Fatalf("EffectiveSoMarkFromDae(0) = %#x, want %#x", got, InternalSoMarkFromDae)
	}
}

func TestEffectiveSoMarkFromDaePreservesConfiguredMark(t *testing.T) {
	const configured uint32 = 0x2023
	if got := EffectiveSoMarkFromDae(configured); got != configured {
		t.Fatalf("EffectiveSoMarkFromDae(%#x) = %#x, want %#x", configured, got, configured)
	}
}

func TestResolveSoMarkFromDaeAutoSelectsInternalMarkWhenUnset(t *testing.T) {
	got, autoSelected := ResolveSoMarkFromDae(0, false)
	if got != InternalSoMarkFromDae {
		t.Fatalf("ResolveSoMarkFromDae(0, false) mark = %#x, want %#x", got, InternalSoMarkFromDae)
	}
	if !autoSelected {
		t.Fatal("ResolveSoMarkFromDae(0, false) should report autoSelected")
	}
}

func TestResolveSoMarkFromDaeKeepsExplicitZeroSilent(t *testing.T) {
	got, autoSelected := ResolveSoMarkFromDae(0, true)
	if got != InternalSoMarkFromDae {
		t.Fatalf("ResolveSoMarkFromDae(0, true) mark = %#x, want %#x", got, InternalSoMarkFromDae)
	}
	if autoSelected {
		t.Fatal("ResolveSoMarkFromDae(0, true) should not report autoSelected")
	}
}

func TestParsePortRange(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr string
	}{
		{"single port", "80", ""},
		{"lower bound", "0", ""},
		{"upper bound", "65535", ""},
		{"same endpoints", "80-80", ""},
		{"ascending", "80-443", ""},
		{"full range", "0-65535", ""},
		{"reversed", "8080-80", "bad port range"},
		{"reversed small", "2-1", "bad port range"},
		{"reversed bounds", "65535-0", "bad port range"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParsePortRange(c.in)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("ParsePortRange(%q) = %v, want nil", c.in, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("ParsePortRange(%q) = %v, want error containing %q", c.in, err, c.wantErr)
			}
		})
	}
}

func TestEnsureFileInSubDir(t *testing.T) {
	cases := []struct {
		name     string
		filePath string
		dir      string
		wantErr  bool
	}{
		{"inside", "/base/sub/file.txt", "/base", false},
		{"sibling with dot-dot-dot name", "/base/...hidden/file.txt", "/base", false},
		{"direct parent", "/other/file.txt", "/base", true},
		{"parent via component", "/base/../other/file.txt", "/base", true},
		{"same dir file", "/base/file.txt", "/base", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := EnsureFileInSubDir(c.filePath, c.dir)
			if (err != nil) != c.wantErr {
				t.Fatalf("EnsureFileInSubDir(%q, %q) err = %v, wantErr = %v",
					c.filePath, c.dir, err, c.wantErr)
			}
		})
	}
}
