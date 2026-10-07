/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

// The event rate-limit constants are owned by Go (event_rate_contract.go) and
// injected into the .rodata variable EVENT_RATE at load time; the bpf_stats_map
// key domain is owned by C and read back by Go. These tests pin both halves of
// the contract at the source level, so a C-side rename, field reorder,
// fallback-constant drift or key renumbering turns the Go Unit Test gate red
// instead of silently falling back to clang initializers (or reading the wrong
// counter) at runtime.

var (
	// matches "const volatile struct dae_event_rate EVENT_RATE = { ... };"
	// and captures the struct tag name and the variable name.
	rodataVariablePattern = regexp.MustCompile(`(?m)const\s+volatile\s+struct\s+(\w+)\s+(\w+)\s*=`)

	// captures the declared field names of struct dae_event_rate in order.
	eventRateStructPattern = regexp.MustCompile(
		`struct\s+dae_event_rate\s*\{([^}]*)\}`)

	// captures " #define EVENT_RATE_KEY_MAX_FALLBACK <n>".
	rateKeyFallbackPattern = regexp.MustCompile(`(?m)#define\s+EVENT_RATE_KEY_MAX_FALLBACK\s+(\d+)`)

	// captures the body of "enum bpf_stats_key { ... }".
	bpfStatsEnumPattern = regexp.MustCompile(`enum\s+bpf_stats_key\s*\{([^}]*)\}`)

	// captures the body of "enum dae_event_type { ... }".
	daeEventTypeEnumPattern = regexp.MustCompile(`enum\s+dae_event_type\s*\{([^}]*)\}`)

	// captures "NAME = <n>" entries inside an enum body. Anchored at the start
	// of a line so the comment lines ("// key=0: ...") of the C enum do not
	// count as entries.
	enumEntryPattern = regexp.MustCompile(`(?m)^\s*(\w+)\s*=\s*(\d+)`)

	// captures " #define MAX_REDIRECT_TRACK_NUM <n>".
	redirectTrackNumPattern = regexp.MustCompile(`(?m)#define\s+MAX_REDIRECT_TRACK_NUM\s+(\d+)`)

	// captures " #define REDIRECT_REBIND_STALE_NS_FALLBACK <n>".
	redirectRebindStalePattern = regexp.MustCompile(`(?m)#define\s+REDIRECT_REBIND_STALE_NS_FALLBACK\s+(\d+)U?LL?`)

	// captures the body of "struct routing_result { ... }".
	routingResultStructPattern = regexp.MustCompile(
		`struct\s+routing_result\s*\{([^}]*)\}`)

	// captures the complete declaration "struct routing_result { ... } ... ;",
	// attributes included, so the C-compiler oracle compiles exactly the
	// declaration the kernel compiles instead of a reconstruction of it.
	routingResultDeclarationPattern = regexp.MustCompile(
		`struct\s+routing_result\s*\{[^}]*\}\s*[^;]*;`)

	// captures what sits between that closing brace and the terminating
	// semicolon. A struct-level attribute (e.g. __attribute__((aligned(16))))
	// raises sizeof and moves every field offset without touching a single
	// field declaration, so the field parser cannot see it.
	routingResultTrailerPattern = regexp.MustCompile(
		`struct\s+routing_result\s*\{[^}]*\}\s*([^;]*);`)

	// captures the body of "type bpfRoutingResult struct { ... }" in the
	// real-datapath mirror, which the stub build cannot compile.
	goRoutingResultStructPattern = regexp.MustCompile(
		`type\s+bpfRoutingResult\s+struct\s*\{([^}]*)\}`)

	// captures " #define NAME <n>" so macro-sized C arrays (e.g.
	// TASK_COMM_LEN) resolve without a second owner of the value.
	cDefinePattern = regexp.MustCompile(`(?m)#define\s+(\w+)\s+(\d+)`)

	// captures one `type name` or `type name[N]` struct field declaration.
	// Every declaration of a mirrored struct must match it, so a field of an
	// unrecognized shape cannot drop out of the layout contract silently.
	cDeclarationPattern = regexp.MustCompile(`^(.+?)\s+(\w+)\s*(?:\[\s*(\w+)\s*\])?$`)
)

// cIntTypeWidths maps the fixed-width C integer types used by
// struct routing_result to their byte widths. A type that is missing here fails
// the layout test instead of being skipped, so a new C field cannot slip past
// the contract unnoticed.
var cIntTypeWidths = map[string]int{
	"__u8":  1,
	"__u16": 2,
	"__u32": 4,
	"__u64": 8,
	"__s8":  1,
	"__s16": 2,
	"__s32": 4,
	"__s64": 8,
	"bool":  1,
	"_Bool": 1,
}

func TestBpfVariablesParityWithKernelSource(t *testing.T) {
	found := map[string]string{} // variable name -> struct tag name
	for _, m := range rodataVariablePattern.FindAllStringSubmatch(tproxySource, -1) {
		found[m[2]] = m[1]
	}

	for _, name := range expectedInjectedVariables {
		tag, ok := found[name]
		if !ok {
			t.Errorf("kernel source declares no `const volatile struct ... %s`; "+
				"bpf_utils.go injects it but the C-side declaration is gone "+
				"(renamed or removed?)", name)
			continue
		}
		if tag != "dae_param" && tag != "dae_event_rate" {
			t.Errorf("variable %s has unexpected struct type %q", name, tag)
		}
	}

	// The reverse direction: every const-volatile struct variable in the
	// kernel source must be covered by the Go injection list, otherwise it
	// would silently keep its clang fallback value in production.
	for name := range found {
		listed := slices.Contains(expectedInjectedVariables, name)
		if !listed {
			t.Errorf("kernel source declares const-volatile variable %q but "+
				"expectedInjectedVariables does not list it; it would keep its "+
				"clang fallback initializer instead of being injected by Go", name)
		}
	}
}

// stripCKernelComments removes block and line comments so source assertions
// match code only (the comments next to the raw-byte accessors quote the very
// expressions this test forbids).
func stripCKernelComments(src string) string {
	src = blockCommentPattern.ReplaceAllString(src, "")
	return lineCommentPattern.ReplaceAllString(src, "")
}

// stripGoComments removes // and /* */ comments so a declaration scan cannot be
// satisfied by the type quoted inside a comment; string, rune and raw-string
// literals are copied verbatim so a comment marker inside one cannot truncate
// the rest of the file.
func stripGoComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	for i := 0; i < len(src); {
		switch {
		case strings.HasPrefix(src[i:], "//"):
			if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = len(src)
			}
		case strings.HasPrefix(src[i:], "/*"):
			j := strings.Index(src[i+2:], "*/")
			if j < 0 {
				i = len(src)
			} else {
				b.WriteByte('\n')
				i += j + 4
			}
		case src[i] == '"' || src[i] == '\'' || src[i] == '`':
			quote := src[i]
			b.WriteByte(quote)
			i++
			for i < len(src) {
				if src[i] == '\\' && quote != '`' {
					b.WriteByte(src[i])
					i++
					if i == len(src) {
						break
					}
					b.WriteByte(src[i])
					i++
					continue
				}
				b.WriteByte(src[i])
				i++
				if src[i-1] == quote {
					break
				}
			}
		default:
			b.WriteByte(src[i])
			i++
		}
	}
	return b.String()
}

var (
	blockCommentPattern = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentPattern  = regexp.MustCompile(`//[^\n]*`)

	// UAPI bitfields of struct iphdr/struct tcphdr. Their allocation order
	// follows the target's endianness, not the wire format, so reading them
	// directly made the datapath classify packets wrongly on big-endian
	// builds (P1-1). The datapath must only touch the raw header bytes.
	bitfieldReadPattern = regexp.MustCompile(`->(ihl|version|doff|syn|ack|fin|rst|psh|ece|cwr|urg|res1)\b`)
)

func TestKernelSourceHasNoBitfieldHeaderReads(t *testing.T) {
	code := stripCKernelComments(tproxySource)
	// ctx->ihl is the parser scratch field (a plain __u8), not the UAPI
	// bitfield of struct iphdr.
	code = strings.ReplaceAll(code, "ctx->ihl", "ctx->scratch_ihl")

	for _, m := range bitfieldReadPattern.FindAllString(code, -1) {
		t.Errorf("kern/tproxy.c reads the UAPI bitfield %q; use the raw-byte "+
			"accessors (iphdr_ihl/iphdr_version/tcph_doff/tcph_flags) instead: "+
			"the bitfield layout is target-endian and misparses on big-endian builds", m)
	}
}

func TestEventRateStructLayoutContract(t *testing.T) {
	// Same two fail-closed rules as struct routing_result: the declaration is
	// read out of code rather than prose and must be unique, and every field
	// declaration must parse, so an added field cannot fall out of the contract.
	kernelSource := stripCKernelComments(tproxySource)
	declarations := eventRateStructPattern.FindAllStringSubmatch(kernelSource, -1)
	if len(declarations) != 1 {
		t.Fatalf("kern/tproxy.c contains %d definitions of struct dae_event_rate, want exactly 1; the gate must not guess which one compiles", len(declarations))
	}
	m := declarations[0]
	var signatures []string
	offset, maxAlign := 0, 1
	for _, decl := range strings.Split(m[1], ";") {
		decl = strings.TrimSpace(decl)
		if decl == "" {
			continue
		}
		fm := cDeclarationPattern.FindStringSubmatch(decl)
		if fm == nil {
			t.Fatalf("struct dae_event_rate declares %q, which is not a plain `type name` or `type name[N]` field; the Go mirror is binary-injected, so every field must be accounted for here", decl)
		}
		width, ok := cIntTypeWidths[fm[1]]
		if !ok {
			t.Fatalf("struct dae_event_rate field %s has unmapped C type %s; add its width to cIntTypeWidths so the field cannot bypass the layout contract", fm[2], fm[1])
		}
		size, signature := width, fm[1]+" "+fm[2]
		if fm[3] != "" {
			count, err := strconv.Atoi(fm[3])
			if err != nil {
				t.Fatalf("struct dae_event_rate field %s has non-numeric array size %q", fm[2], fm[3])
			}
			size, signature = width*count, signature+"["+fm[3]+"]"
		}
		if width > maxAlign {
			maxAlign = width
		}
		offset = (offset + width - 1) / width * width
		offset += size
		signatures = append(signatures, signature)
	}

	// Two u64 fields first (so the struct has no implicit padding between
	// them), then the reserved rate keys, then an explicit pad that keeps the
	// C sizeof free of alignment holes. eventRateValue() mirrors this order
	// with an explicit trailing byte array to match the C sizeof; the parity
	// of the two sizes is enforced at load time by ebpf.VariableSpec.Set.
	// Signatures, not names: a field silently widened to u64 would keep the
	// name order and still change the mirrored size.
	want := []string{
		"__u64 window_ns",
		"__u64 redirect_rebind_stale_ns",
		"__u32 blocked_key",
		"__u32 redirect_rebind_key",
		"__u32 overflow_key",
		"__u32 syn_rebind_key",
		"__u32 stateless_tcp_key",
		"__u32 frag_tail_key",
		"__u32 padding[2]",
	}
	if !reflect.DeepEqual(signatures, want) {
		t.Fatalf("struct dae_event_rate declares %v, want %v (no implicit padding and no extra field allowed: the Go mirror is binary-injected)", signatures, want)
	}
	if size := (offset + maxAlign - 1) / maxAlign * maxAlign; size != 48 {
		t.Fatalf("struct dae_event_rate sizes to %d bytes, want the 48 bytes eventRateValue() encodes", size)
	}
}

func TestEventRateValueMatchesContract(t *testing.T) {
	// Anchors the injected value (and the contract symbols) in the
	// dae_stub_ebpf build, where bpf_utils.go — the production consumer —
	// is excluded: without this reference the mirror would be flagged
	// unused by the stub-tagged lint pass.
	v := eventRateValue()
	if v.WindowNs != blockedEventRateWindowNs {
		t.Fatalf("EVENT_RATE window %d != contract %d", v.WindowNs, blockedEventRateWindowNs)
	}
	if v.RedirectRebindStaleNs != redirectRebindStaleNs {
		t.Fatalf("EVENT_RATE rebind window %d != contract %d", v.RedirectRebindStaleNs, redirectRebindStaleNs)
	}
	if v.BlockedKey != blockedEventRateKey {
		t.Fatalf("EVENT_RATE blocked key %d != contract %d", v.BlockedKey, blockedEventRateKey)
	}
	if v.RedirectRebindKey != redirectRebindEventRateKey {
		t.Fatalf("EVENT_RATE redirect rebind key %d != contract %d", v.RedirectRebindKey, redirectRebindEventRateKey)
	}
	if v.OverflowKey != overflowEventRateKey {
		t.Fatalf("EVENT_RATE overflow key %d != contract %d", v.OverflowKey, overflowEventRateKey)
	}
	if v.SynRebindKey != synRebindEventRateKey {
		t.Fatalf("EVENT_RATE syn rebind key %d != contract %d", v.SynRebindKey, synRebindEventRateKey)
	}
	if v.StatelessTCPKey != statelessTCPEventRateKey {
		t.Fatalf("EVENT_RATE stateless TCP key %d != contract %d", v.StatelessTCPKey, statelessTCPEventRateKey)
	}
	if v.FragTailKey != fragTailEventRateKey {
		t.Fatalf("EVENT_RATE fragment tail key %d != contract %d", v.FragTailKey, fragTailEventRateKey)
	}
}

func TestEventRateFallbackConstantsMatchGoOwner(t *testing.T) {
	m := rateKeyFallbackPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("#define EVENT_RATE_KEY_MAX_FALLBACK not found in kern/tproxy.c")
	}
	fallback, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		t.Fatalf("parse fallback key %q: %v", m[1], err)
	}
	if uint32(fallback) != eventRateMapKeyMax {
		t.Fatalf("C fallback EVENT_RATE_KEY_MAX_FALLBACK=%d diverges from the Go-owned eventRateMapKeyMax=%d; the map capacity derives from the Go value while the C code uses the fallback",
			fallback, eventRateMapKeyMax)
	}
	rebind := redirectRebindStalePattern.FindStringSubmatch(tproxySource)
	if rebind == nil {
		t.Fatal("#define REDIRECT_REBIND_STALE_NS_FALLBACK not found in kern/tproxy.c")
	}
	stale, err := strconv.ParseUint(rebind[1], 10, 64)
	if err != nil {
		t.Fatalf("parse rebind window %q: %v", rebind[1], err)
	}
	if stale != redirectRebindStaleNs {
		t.Fatalf("C fallback REDIRECT_REBIND_STALE_NS_FALLBACK=%d diverges from the Go-owned redirectRebindStaleNs=%d", stale, redirectRebindStaleNs)
	}
}

// TestDaeEventTypeNumbersMatchKernelSource pins the ringbuf event numbering
// against the Go iota table in event_ringbuf.go. The numbers are a wire
// contract: the kernel writes the type into the record and userspace decodes it
// without any other discriminator, so an inserted or removed entry on either
// side silently turns one event into another. Two of the entries are reserved
// (established TCP without cached routing, forwarded fragment tails) because
// they are counted and summarised instead of emitted; this test is what keeps
// them reserved and keeps the emitted types on their historical numbers.
func TestDaeEventTypeNumbersMatchKernelSource(t *testing.T) {
	m := daeEventTypeEnumPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("enum dae_event_type not found in kern/tproxy.c")
	}
	cTypes := map[string]uint32{}
	for _, em := range enumEntryPattern.FindAllStringSubmatch(m[1], -1) {
		value, err := strconv.ParseUint(em[2], 10, 32)
		if err != nil {
			t.Fatalf("parse enum entry %s: %v", em[0], err)
		}
		cTypes[em[1]] = uint32(value)
	}

	contract := []struct {
		cName  string
		goType uint32
	}{
		{"DAE_EVENT_BLOCKED", daeEventBlocked},
		{"DAE_EVENT_UDP_CONN_OVERFLOW", daeEventUdpConnOverflow},
		{"DAE_EVENT_TCP_CONN_OVERFLOW", daeEventTcpConnOverflow},
		{"DAE_EVENT_BLOCKED_ALIVE", daeEventBlockedAlive},
		{"DAE_EVENT_REDIRECT_REBIND_REJECTED", daeEventRedirectRebindRejected},
		{"DAE_EVENT_SYN_REBIND_REJECTED", daeEventSynRebindRejected},
		{"DAE_EVENT_RESERVED_STATELESS_TCP_PASSTHROUGH", daeEventReservedStatelessTcpPassthrough},
		{"DAE_EVENT_RESERVED_FRAG_TAIL_PASSED", daeEventReservedFragTailPassed},
		{"DAE_EVENT_REDIRECT_UPDATE_FAILED", daeEventRedirectUpdateFailed},
		{"DAE_EVENT_SYN_REBIND_REROUTED", daeEventSynRebindRerouted},
	}
	for _, entry := range contract {
		value, ok := cTypes[entry.cName]
		if !ok {
			t.Errorf("enum dae_event_type has no %s entry", entry.cName)
			continue
		}
		if value != entry.goType {
			t.Errorf("event type %s = %d in C but %d in Go; the ringbuf consumer would decode it as another event",
				entry.cName, value, entry.goType)
		}
	}
	if len(cTypes) != len(contract) {
		t.Errorf("enum dae_event_type declares %d entries but Go mirrors %d; every emitted type needs a Go-side decoder (or the enum has a stale entry)",
			len(cTypes), len(contract))
	}
}

// TestBpfStatsKeysParityWithKernelSource pins the bpf_stats_map key domain:
// every counter Go reads back must exist in enum bpf_stats_key with the same
// number, the enum must not carry keys Go does not know about, and the ARRAY
// capacity must be the terminal enum entry.
func TestBpfStatsKeysParityWithKernelSource(t *testing.T) {
	m := bpfStatsEnumPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("enum bpf_stats_key not found in kern/tproxy.c")
	}
	cKeys := map[string]uint32{}
	for _, em := range enumEntryPattern.FindAllStringSubmatch(m[1], -1) {
		value, err := strconv.ParseUint(em[2], 10, 32)
		if err != nil {
			t.Fatalf("parse enum entry %s: %v", em[0], err)
		}
		cKeys[em[1]] = uint32(value)
	}

	contract := []struct {
		cName string
		goKey uint32
	}{
		{"BPF_STATS_UDP_CONN_OVERFLOW", bpfStatsUDPConnOverflow},
		{"BPF_STATS_TCP_CONN_OVERFLOW", bpfStatsTCPConnOverflow},
		{"BPF_STATS_REDIRECT_OVERFLOW", bpfStatsRedirectOverflow},
		{"BPF_STATS_REDIRECT_UPDATE_FAILED", bpfStatsRedirectUpdateFailed},
		{"BPF_STATS_REDIRECT_REBIND_REJECTED", bpfStatsRedirectRebindRejected},
		{"BPF_STATS_SYN_REBIND_REJECTED", bpfStatsSynRebindRejected},
		{"BPF_STATS_STATELESS_TCP_PASSTHROUGH", bpfStatsStatelessTCPPassthrough},
		{"BPF_STATS_FRAG_TAIL_PASSED", bpfStatsFragTailPassed},
		{"BPF_STATS_PARSE_UNSUPPORTED_L4", bpfStatsParseUnsupportedL4},
		{"BPF_STATS_UNSOLICITED_UDP_SEEN", bpfStatsUnsolicitedUDPSeen},
		{"BPF_STATS_SOCKMARK_FALLBACK", bpfStatsSockmarkFallback},
		{"BPF_STATS_EVENT_DROP", bpfStatsEventDrop},
		{"BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE", bpfStatsRebindReroutedAfterEpochChange},
	}
	for _, entry := range contract {
		value, ok := cKeys[entry.cName]
		if !ok {
			t.Errorf("enum bpf_stats_key has no %s entry", entry.cName)
			continue
		}
		if value != entry.goKey {
			t.Errorf("bpf_stats_map key %s = %d in C but %d in Go; the Go reader would read the wrong counter",
				entry.cName, value, entry.goKey)
		}
	}

	// BPF_STATS_MAX is the ARRAY capacity, i.e. one past the last valid key. It
	// is derived from the table above instead of being mirrored as a Go
	// constant: adding a key in C without covering it here then fails, and the
	// Go side never owns a second copy of the C macro.
	if got := cKeys["BPF_STATS_MAX"]; got != uint32(len(contract)) {
		t.Errorf("BPF_STATS_MAX = %d in C but %d keys are covered here", got, len(contract))
	}
	// The C enum carries one entry that is not a key: BPF_STATS_MAX, the array
	// capacity. Counting it separately keeps both invariants without a Go-side
	// copy of the C macro (a Go mirror would be a second owner of that value).
	if len(cKeys) != len(contract)+1 {
		t.Errorf("enum bpf_stats_key declares %d entries (%d keys plus BPF_STATS_MAX) but Go mirrors %d keys; every key needs a Go-side reader (or the enum has a stale entry)",
			len(cKeys), len(contract), len(contract))
	}
	if !regexp.MustCompile(`__uint\(max_entries,\s*BPF_STATS_MAX\)`).MatchString(tproxySource) {
		t.Error("bpf_stats_map must size itself from BPF_STATS_MAX so the ARRAY capacity cannot drift from the enum")
	}
}

// TestRedirectTrackCapacityParityWithKernelSource pins the single-owner
// contract of tuneRedirectTrackMap: the Go default must mirror the C map
// declaration, which is what makes the load-time cross-check meaningful.
func TestRedirectTrackCapacityParityWithKernelSource(t *testing.T) {
	m := redirectTrackNumPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("#define MAX_REDIRECT_TRACK_NUM not found in kern/tproxy.c")
	}
	want, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		t.Fatalf("parse MAX_REDIRECT_TRACK_NUM %q: %v", m[1], err)
	}
	if uint32(want) != defaultRedirectTrackMapMaxEntries {
		t.Fatalf("C MAX_REDIRECT_TRACK_NUM=%d diverges from Go defaultRedirectTrackMapMaxEntries=%d; tuneRedirectTrackMap cross-checks the compiled capacity against the Go value and would fail the load",
			want, defaultRedirectTrackMapMaxEntries)
	}
}

// TestRoutingResultLayoutParityWithKernelSource pins the hand-written Go
// mirror bpfRoutingResult (control/bpf_utils.go in the real build,
// control/bpf_stub.go here) against struct routing_result in kern/tproxy.c.
// The mirror is not bpf2go-generated, so nothing else fails when only the C
// side drifts: a reordered, re-typed or resized C field would silently
// misread every routing decision userspace copies from the kernel. The test
// pins field order, per-field byte width and the byte offsets that
// unsafe.Offsetof computes on the Go side. It carries no build tag, so it runs
// in both the stub and the real-datapath build; the mirror that the current
// build cannot compile is covered by TestRoutingResultMirrorSourcesAgree.
// routingResultContract pairs each C field of struct routing_result with its Go
// mirror field, in declaration order. The source-level gate and the C-compiler
// oracle below both read this one list.
var routingResultContract = []struct{ cName, goName string }{
	{"mark", "Mark"},
	{"must", "Must"},
	{"mac", "Mac"},
	{"outbound", "Outbound"},
	{"pname", "Pname"},
	{"pid", "Pid"},
	{"dscp", "Dscp"},
	{"routing_epoch_slot", "RoutingEpochSlot"},
	{"datapath_generation", "DatapathGeneration"},
}

// goRoutingResultOffsets returns the compiled offset of every Go mirror field.
// unsafe.Offsetof makes the compiler's layout, not a repeated table, the source
// of truth.
func goRoutingResultOffsets() map[string]uintptr {
	var r bpfRoutingResult
	return map[string]uintptr{
		"Mark":               unsafe.Offsetof(r.Mark),
		"Must":               unsafe.Offsetof(r.Must),
		"Mac":                unsafe.Offsetof(r.Mac),
		"Outbound":           unsafe.Offsetof(r.Outbound),
		"Pname":              unsafe.Offsetof(r.Pname),
		"Pid":                unsafe.Offsetof(r.Pid),
		"Dscp":               unsafe.Offsetof(r.Dscp),
		"RoutingEpochSlot":   unsafe.Offsetof(r.RoutingEpochSlot),
		"DatapathGeneration": unsafe.Offsetof(r.DatapathGeneration),
	}
}

func TestRoutingResultLayoutParityWithKernelSource(t *testing.T) {
	kernelSource := stripCKernelComments(tproxySource)
	// Fail closed on ambiguity: a second definition (a disabled block, a quoted
	// declaration) must not be able to stand in for the one that compiles.
	declarations := routingResultStructPattern.FindAllStringSubmatch(kernelSource, -1)
	if len(declarations) != 1 {
		t.Fatalf("kern/tproxy.c contains %d definitions of struct routing_result, want exactly 1; the gate must not guess which one compiles", len(declarations))
	}
	m := declarations[0]
	// A struct-level attribute changes the layout of every field at once, so
	// the field-by-field comparison below could not notice it.
	trailer := routingResultTrailerPattern.FindStringSubmatch(kernelSource)
	if trailer == nil {
		t.Fatal("struct routing_result is not terminated by a plain `};` in kern/tproxy.c")
	}
	if extra := strings.TrimSpace(trailer[1]); extra != "" {
		t.Fatalf("struct routing_result carries %q between its closing brace and the terminating semicolon; a struct-level attribute can change sizeof and every field offset without touching a field declaration, so the Go mirror must be re-derived and this test taught to size the attribute before adding one", extra)
	}

	// The Go mirror of struct routing_result, in declaration order: the C
	// name keys the parsed field, the Go name keys the offset table below.

	macros := map[string]int{}
	for _, dm := range cDefinePattern.FindAllStringSubmatch(tproxySource, -1) {
		if v, err := strconv.Atoi(dm[2]); err == nil {
			macros[dm[1]] = v
		}
	}

	// Parse "type name;" and "type name[n];" declarations: width is the
	// element width times the element count, alignment the element width. Every
	// declaration in the body must resolve: scanning only for known types would
	// let a field of an unrecognized type (a signed int, a bitfield, a nested
	// aggregate) drop out of the layout routingResultContract silently.
	type cField struct {
		name  string
		size  int
		align int
	}
	var cFields []cField
	for _, decl := range strings.Split(m[1], ";") {
		decl = strings.TrimSpace(decl)
		if decl == "" {
			continue
		}
		fm := cDeclarationPattern.FindStringSubmatch(decl)
		if fm == nil {
			t.Fatalf("struct routing_result declares %q, which is not a plain `type name` or `type name[N]` field; size it here before adding it to the Go mirror", decl)
		}
		elemWidth, ok := cIntTypeWidths[fm[1]]
		if !ok {
			t.Fatalf("struct routing_result field %s has unmapped C type %s; add its width to cIntTypeWidths so the field cannot bypass the layout routingResultContract", fm[2], fm[1])
		}
		size := elemWidth
		if array := fm[3]; array != "" {
			elems, err := strconv.Atoi(array)
			if err != nil {
				elems, ok = macros[array]
				if !ok {
					t.Fatalf("struct routing_result field %s has unknown array size %q", fm[2], array)
				}
			}
			size = elemWidth * elems
		}
		cFields = append(cFields, cField{name: fm[2], size: size, align: elemWidth})
	}
	if len(cFields) != len(routingResultContract) {
		t.Fatalf("struct routing_result declares %d fields (%v) but the Go mirror bpfRoutingResult has %d; both sides must change together",
			len(cFields), cFields, len(routingResultContract))
	}

	// Go side: order and sizes from the real type, offsets from
	// unsafe.Offsetof so the compiler's layout is what gets pinned.
	var goResult bpfRoutingResult
	goOffsets := goRoutingResultOffsets()
	goType := reflect.TypeFor[bpfRoutingResult]()
	var goNames []string
	goSizes := map[string]int{}
	for field := range goType.Fields() {
		if field.Name == "_" {
			// Zero-size host-layout marker of the stub mirror.
			continue
		}
		goNames = append(goNames, field.Name)
		goSizes[field.Name] = int(field.Type.Size())
	}

	cOffset, maxAlign := 0, 1
	for i, want := range routingResultContract {
		got := cFields[i]
		if got.name != want.cName {
			t.Fatalf("struct routing_result field %d is %q but the Go mirror expects %q at that position; a reorder silently misreads every routing decision",
				i, got.name, want.cName)
		}
		if i >= len(goNames) || goNames[i] != want.goName {
			t.Fatalf("bpfRoutingResult field order %v does not mirror the routingResultContract entry %q", goNames, want.goName)
		}
		if got.align > maxAlign {
			maxAlign = got.align
		}
		cOffset = (cOffset + got.align - 1) / got.align * got.align
		if goOffsets[want.goName] != uintptr(cOffset) {
			t.Fatalf("field %s sits at C offset %d but Go offset %d in bpfRoutingResult", want.goName, cOffset, goOffsets[want.goName])
		}
		if goSizes[want.goName] != got.size {
			t.Fatalf("field %s is %d bytes in C but %d in Go", want.goName, got.size, goSizes[want.goName])
		}
		cOffset += got.size
	}
	cOffset = (cOffset + maxAlign - 1) / maxAlign * maxAlign
	if size := unsafe.Sizeof(goResult); size != uintptr(cOffset) {
		t.Fatalf("struct routing_result is %d bytes in C but bpfRoutingResult is %d in Go", cOffset, size)
	}
}

// TestRoutingResultLayoutMatchesCCompiler asks a real C compiler for the
// sizeof and offsetof of the declaration in kern/tproxy.c and compares them with
// the compiled Go mirror. The source-level gate re-implements C alignment rules
// in Go, so an attribute, pragma or compiler flag that changes the layout can
// only be caught by the oracle. It also pins that -fpack-struct leaves this
// struct unchanged: every field is already naturally packed, which is what lets
// the hand-written Go mirror match the unpacked declaration.
func TestRoutingResultLayoutMatchesCCompiler(t *testing.T) {
	cc, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("no C compiler available to size the kernel struct: %v", err)
	}
	kernelSource := stripCKernelComments(tproxySource)
	declarations := routingResultDeclarationPattern.FindAllString(kernelSource, -1)
	if len(declarations) != 1 {
		t.Fatalf("kern/tproxy.c contains %d declarations of struct routing_result, want exactly 1", len(declarations))
	}

	var probe strings.Builder
	probe.WriteString("/* generated by control/bpf_variables_parity_test.go */\n")
	probe.WriteString("#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n")
	probe.WriteString("typedef uint8_t __u8; typedef uint16_t __u16; typedef uint32_t __u32; typedef uint64_t __u64;\n")
	for _, dm := range cDefinePattern.FindAllStringSubmatch(kernelSource, -1) {
		fmt.Fprintf(&probe, "#define %s %s\n", dm[1], dm[2])
	}
	probe.WriteString(declarations[0])
	probe.WriteString("\nint main(void) {\n")
	probe.WriteString("\tprintf(\"sizeof %zu\\n\", sizeof(struct routing_result));\n")
	for _, entry := range routingResultContract {
		fmt.Fprintf(&probe, "\tprintf(\"%s %%zu\\n\", offsetof(struct routing_result, %s));\n", entry.cName, entry.cName)
	}
	probe.WriteString("\treturn 0;\n}\n")

	goResult := bpfRoutingResult{}
	goOffsets := goRoutingResultOffsets()
	layout := func(variant string, flags ...string) map[string]int {
		t.Helper()
		dir := t.TempDir()
		source := filepath.Join(dir, "layout.c")
		if err := os.WriteFile(source, []byte(probe.String()), 0o600); err != nil {
			t.Fatalf("write the %s C probe: %v", variant, err)
		}
		binary := filepath.Join(dir, "layout")
		args := append([]string{"-std=gnu11", "-O0", "-o", binary, source}, flags...)
		if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s C probe did not compile: %v\n%s", variant, err, out)
		}
		out, err := exec.Command(binary).Output()
		if err != nil {
			t.Fatalf("run the %s C probe: %v", variant, err)
		}
		got := map[string]int{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			name, value, ok := strings.Cut(line, " ")
			if !ok {
				t.Fatalf("%s C probe printed %q, want `name value`", variant, line)
			}
			n, err := strconv.Atoi(value)
			if err != nil {
				t.Fatalf("%s C probe printed %q: %v", variant, line, err)
			}
			got[name] = n
		}
		if size := int(unsafe.Sizeof(goResult)); got["sizeof"] != size {
			t.Fatalf("%s: the C compiler sizes struct routing_result to %d bytes but bpfRoutingResult is %d; the Go mirror must match the declaration the compiler sees", variant, got["sizeof"], size)
		}
		for _, entry := range routingResultContract {
			if got[entry.cName] != int(goOffsets[entry.goName]) {
				t.Fatalf("%s: field %s sits at C offset %d but Go offset %d in bpfRoutingResult", variant, entry.goName, got[entry.cName], goOffsets[entry.goName])
			}
		}
		return got
	}

	if len(cDefinePattern.FindAllStringSubmatch(kernelSource, -1)) == 0 {
		t.Fatal("kern/tproxy.c declares no #define, so the C probe cannot resolve macro-sized fields")
	}
	unpacked := layout("default")
	packed := layout("-fpack-struct", "-fpack-struct")
	for name, offset := range unpacked {
		if packed[name] != offset {
			t.Fatalf("-fpack-struct moves %s from %d to %d: the Go mirror is written for the unpacked declaration, so this struct must stay free of implicit alignment holes (or both mirrors must be re-derived together)", name, offset, packed[name])
		}
	}
}

// TestRoutingResultMirrorSourcesAgree pins the real-datapath mirror
// declaration in control/bpf_utils.go to the compiled bpfRoutingResult. The two
// mirrors are hand-written and live behind opposite build tags, so the layout
// test above only ever sees one of them: without this check, editing only
// bpf_utils.go keeps the stub unit-test gate green while the binary that ships
// decodes the kernel struct with different field types or offsets.
func TestRoutingResultMirrorSourcesAgree(t *testing.T) {
	// The declaration must be read out of code, not out of prose: a doc comment
	// quoting the type (or a second definition) would otherwise decide what the
	// gate compares, and the shipped mirror could drift behind it.
	declarations := goRoutingResultStructPattern.FindAllStringSubmatch(stripGoComments(bpfUtilsSource), -1)
	if len(declarations) != 1 {
		t.Fatalf("control/bpf_utils.go contains %d definitions of type bpfRoutingResult struct, want exactly 1; the gate must not guess which one ships", len(declarations))
	}
	m := declarations[0]

	var want []string
	for _, line := range strings.Split(m[1], "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			t.Fatalf("control/bpf_utils.go declares %q, which is not a plain `Name Type` field", strings.TrimSpace(line))
		}
		if fields[0] == "_" {
			// Zero-size host-layout marker, absent from the real mirror.
			continue
		}
		want = append(want, fields[0]+" "+fields[1])
	}

	var got []string
	for field := range reflect.TypeFor[bpfRoutingResult]().Fields() {
		if field.Name == "_" {
			// Zero-size host-layout marker of the stub mirror.
			continue
		}
		got = append(got, field.Name+" "+field.Type.String())
	}
	if !slices.Equal(want, got) {
		t.Fatalf("control/bpf_utils.go declares bpfRoutingResult fields %v but the compiled mirror has %v; the two hand-written mirrors must stay identical",
			want, got)
	}
}
