/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
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
	m := eventRateStructPattern.FindStringSubmatch(tproxySource)
	if m == nil {
		t.Fatal("struct dae_event_rate not found in kern/tproxy.c")
	}
	fieldPattern := regexp.MustCompile(`(__u\d+|\w+_t)\s+(\w+)\s*;`)
	var fields []string
	for _, fm := range fieldPattern.FindAllStringSubmatch(m[1], -1) {
		fields = append(fields, fm[2])
	}

	// Two u64 fields first (so the struct has no implicit padding between
	// them), then the reserved rate keys, then an explicit pad that keeps the
	// C sizeof free of alignment holes. eventRateValue() mirrors this order
	// with an explicit trailing byte array to match the C sizeof; the parity
	// of the two sizes is enforced at load time by ebpf.VariableSpec.Set.
	want := []string{
		"window_ns",
		"redirect_rebind_stale_ns",
		"blocked_key",
		"redirect_rebind_key",
		"overflow_key",
		"syn_rebind_key",
		"stateless_tcp_key",
		"frag_tail_key",
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("struct dae_event_rate field order %v, want %v (no implicit padding allowed: the Go mirror is binary-injected)", fields, want)
	}
	if !regexp.MustCompile(`__u32\s+padding\s*\[2\]\s*;`).MatchString(m[1]) {
		t.Fatalf("struct dae_event_rate must end with an explicit `__u32 padding[2]` so its sizeof (48) matches the packed Go mirror; body: %s", m[1])
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
func TestRoutingResultLayoutParityWithKernelSource(t *testing.T) {
	kernelSource := stripCKernelComments(tproxySource)
	m := routingResultStructPattern.FindStringSubmatch(kernelSource)
	if m == nil {
		t.Fatal("struct routing_result not found in kern/tproxy.c")
	}
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
	contract := []struct{ cName, goName string }{
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
	// aggregate) drop out of the layout contract silently.
	type cField struct {
		name  string
		size  int
		align int
	}
	declPattern := regexp.MustCompile(`^(.+?)\s+(\w+)\s*(?:\[\s*(\w+)\s*\])?$`)
	var cFields []cField
	for _, decl := range strings.Split(m[1], ";") {
		decl = strings.TrimSpace(decl)
		if decl == "" {
			continue
		}
		fm := declPattern.FindStringSubmatch(decl)
		if fm == nil {
			t.Fatalf("struct routing_result declares %q, which is not a plain `type name` or `type name[N]` field; size it here before adding it to the Go mirror", decl)
		}
		elemWidth, ok := cIntTypeWidths[fm[1]]
		if !ok {
			t.Fatalf("struct routing_result field %s has unmapped C type %s; add its width to cIntTypeWidths so the field cannot bypass the layout contract", fm[2], fm[1])
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
	if len(cFields) != len(contract) {
		t.Fatalf("struct routing_result declares %d fields (%v) but the Go mirror bpfRoutingResult has %d; both sides must change together",
			len(cFields), cFields, len(contract))
	}

	// Go side: order and sizes from the real type, offsets from
	// unsafe.Offsetof so the compiler's layout is what gets pinned.
	var goResult bpfRoutingResult
	goOffsets := map[string]uintptr{
		"Mark":               unsafe.Offsetof(goResult.Mark),
		"Must":               unsafe.Offsetof(goResult.Must),
		"Mac":                unsafe.Offsetof(goResult.Mac),
		"Outbound":           unsafe.Offsetof(goResult.Outbound),
		"Pname":              unsafe.Offsetof(goResult.Pname),
		"Pid":                unsafe.Offsetof(goResult.Pid),
		"Dscp":               unsafe.Offsetof(goResult.Dscp),
		"RoutingEpochSlot":   unsafe.Offsetof(goResult.RoutingEpochSlot),
		"DatapathGeneration": unsafe.Offsetof(goResult.DatapathGeneration),
	}
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
	for i, want := range contract {
		got := cFields[i]
		if got.name != want.cName {
			t.Fatalf("struct routing_result field %d is %q but the Go mirror expects %q at that position; a reorder silently misreads every routing decision",
				i, got.name, want.cName)
		}
		if i >= len(goNames) || goNames[i] != want.goName {
			t.Fatalf("bpfRoutingResult field order %v does not mirror the contract entry %q", goNames, want.goName)
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

// TestRoutingResultMirrorSourcesAgree pins the real-datapath mirror
// declaration in control/bpf_utils.go to the compiled bpfRoutingResult. The two
// mirrors are hand-written and live behind opposite build tags, so the layout
// test above only ever sees one of them: without this check, editing only
// bpf_utils.go keeps the stub unit-test gate green while the binary that ships
// decodes the kernel struct with different field types or offsets.
func TestRoutingResultMirrorSourcesAgree(t *testing.T) {
	m := goRoutingResultStructPattern.FindStringSubmatch(bpfUtilsSource)
	if m == nil {
		t.Fatal("type bpfRoutingResult struct not found in control/bpf_utils.go")
	}

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
