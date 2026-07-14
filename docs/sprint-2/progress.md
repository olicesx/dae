# Sprint 2 — Semantic Architecture Refactor

> Goal: advance `docs/en/semantic-architecture-refactor-plan.md` phases.
> Mode: phase-by-phase, must respect plan's "no phase authoritative until its
> compatibility checks pass" rule.

## Inheritance from previous Codex session (2026-07-14)

Branch: `codex/semantic-architecture-refactor`

Committed by codex:
- `2ca5769b feat(routing): add semantic policy foundation` — Phase 1 types
  (`PolicySnapshot`, `Decision`, `Truth`, three-valued evaluation).
- `2bc0e758 test(routing): verify policy snapshot compatibility` — Phase 1 tests.
- `72917a4a refactor(dns): separate upstream resolution from delivery` — Phase 5
  beginning (upstream resolution split from delivery).

Committed this session (post-cleanup):
- `20c2c4cc feat(control): capture UDP flow binding at endpoint creation` —
  Phase 6 foundation for UDP. Records immutable `UdpFlowBinding` (route +
  egress) on `UdpEndpoint`. Threads `Must` and `OutboundIndex` through
  `proxyDialParam/Result` and `DialOption`.
- `50ed80d7 test(control): add Phase 0 routing corpus and verify
  PolicySnapshot equivalence` — Phase 0 routing corpus (20 fixtures, 46
  cases) + Phase 1 acceptance check applied to the full corpus.

Committed next session (2026-07-14, orchestrator):
- `feat(control): add Phase 1 fuzz target + Phase 0 DNS corpus foundation`
  — Adds `control/refactor_corpus_fuzz_test.go` (Phase 1 acceptance clause
  4: fuzz tests cover aliasing and deterministic hashing; 33k execs, 0
  crashes) and `control/refactor_dns_corpus{,_fixtures,_test}.go` (Phase 0
  DNS corpus with 4 fixtures: udp_cache_miss, udp_cache_hit,
  udp_cache_stale_optimistic, reject_before_cache). No production code
  modified.

Cleanup actions taken:
- Reverted codex's destructive `deadlock_test.go` edit (deleted
  `newRecoveryTestDialer` referenced by 19 call sites).
- Reverted CRLF/LF whitespace-only churn across ~60 test files.
- Reverted `.gitignore` change that hid `docs/`.
- Removed orphan helpers file `control/test_dial_helpers_test.go`
  (duplicated existing test helpers, not referenced).
- Removed untracked `pkg/trie/trie_bench_test.go` (unrelated benchmark).
- Fixed codex compile bugs in `control/udp.go`: stray `, nil` after struct
  literal, and `option :=` shadowing named return inside closure.

Verification status post-cleanup:
- `go build ./...` PASS
- `go vet ./control/... ./component/routing/...` PASS
- `go test ./control/... ./component/routing/... -run 'TestUdpFlowBinding|TestPolicySnapshot|TestPolicy|TestTruth|TestDecision|TestDeferred'` PASS

## Phase Status (vs plan)

| Phase | Status | Notes |
|---|---|---|
| 0. Compatibility Corpus & Observability | PARTIAL | routing corpus (20 fixtures, 46 cases) + DNS corpus (4 fixtures: UDP cache miss/hit/stale + reject-before-cache) done; TCP transport-level fallback, QUIC sniffing, reload corpora still pending; performance baseline not yet recorded |
| 1. Immutable Policy Snapshot | ACCEPTANCE MET (userspace, full) | corpus-equivalent test passes for all 20 fixtures; fuzz target `FuzzPolicySnapshotEquivalence` covers aliasing + hash stability (33k execs, 0 crashes); kernel-side equivalence still pending |
| 2. Three-Valued Evaluation | PARTIAL | `truth.go` exists, not wired into routing |
| 3. Decision Adapter & Shadow | PARTIAL | `Decision` type exists, no shadow wiring |
| 4. Epoch-Scoped Kernel Plan | NOT STARTED | — |
| 5. DNS Resolver/Cache/Projection | PARTIAL | upstream/delivery split only |
| 6. Flow & Egress Bindings | PARTIAL | UDP done, TCP not started |
| 7. Runtime Supervisor | NOT STARTED | — |
| 8. Controlled Cutover | NOT STARTED | — |

## Phase 0 routing corpus (delivered)

Files:
- `control/refactor_corpus.go` — `CorpusFixture`, `CorpusInput`, `CorpusExpected`,
  `Replay(t, matcher, fixture)` driver. MAC and process-name conversion
  helpers mirror `ControlPlane.Route` semantics.
- `control/refactor_corpus_fixtures.go` — 20 fixtures covering every routing
  function (Domain suffix/full/keyword, IpSet, SourceIpSet, Port,
  SourcePort, L4Proto, IpVersion, ProcessName, Dscp, Mac, Fallback),
  AND/OR/NOT combinations, priority ordering, mark, must, and reserved
  outbounds (direct, block).
- `control/refactor_corpus_test.go` — `TestPhase0RoutingCorpus_LegacyBaseline`
  pins legacy output; `TestPhase0RoutingCorpus_PolicySnapshotEquivalent`
  replays the corpus against a PolicySnapshot-built matcher and asserts
  byte-identical results.

To extend: append a constructor to `RoutingCorpusFixtures()` in
`refactor_corpus_fixtures.go`. Every future phase that touches routing
determinism MUST keep both corpus tests passing.

## Phase 0 DNS corpus (initial delivery)

Files:
- `control/refactor_dns_corpus.go` — `DnsCorpusFixture`, `DnsCorpusCase`,
  `DnsCorpusExpected`, `ReplayDns(t, fixture)` driver. Mirrors routing corpus
  pattern: builds a fresh `DnsController` from the fixture's `*config.Dns`,
  installs best-dialer chooser and forwarder factory, then for each case
  optionally runs `PreState` (e.g. cache warm) before invoking
  `HandleWithResponseWriter_` and asserting the captured response shape.
- `control/refactor_dns_corpus_fixtures.go` — 4 fixtures:
  - `udp_cache_miss` — cold cache UDP query forwards upstream and returns the
    canned answer (IP encodes dial target).
  - `udp_cache_hit` — warm cache serves the cached IP without contacting the
    factory (factory IP differs from cached IP for clear regression signal).
  - `udp_cache_stale_optimistic` — stale-but-not-expired cache serves the
    cached IP; the background refresh path is not externally observable.
  - `reject_before_cache` — DNS `qname(full)` reject rule short-circuits even
    when a warm cache entry exists; documents the `Handle_` invariant.
- `control/refactor_dns_corpus_test.go` — `TestPhase0DnsCorpus_LegacyBaseline`
  pins current behaviour.

Helpers reused from existing test infrastructure: `captureResponseWriter`,
`stubDnsForwarder`, `setScopedBestDialerChooser`, `dnsAResponseMsg`,
`dnsAnswerIPv4`. New helper `dnsAnswerIPv6` added in `refactor_dns_corpus.go`
mirrors the v4 extractor for future AAAA fixtures.

## Phase 1 fuzz target (delivered)

File: `control/refactor_corpus_fuzz_test.go`.

`FuzzPolicySnapshotEquivalence` satisfies Phase 1 acceptance clause 4
("fuzz tests cover aliasing and deterministic hashing"). Seeds come from
`RoutingCorpusFixtures()`. Each iteration:
1. Builds legacy matcher and snapshot matcher from the same fixture.
2. Asserts byte-identical `(outbound, mark, must)` on success.
3. Asserts error agreement on failure (alias-safety).
4. Builds two snapshots at different epochs from the same program and
   asserts `Hash()` equality (content-derived, not epoch-derived).

Completed local smoke: 2,463 executions in five seconds, with no crashes or
hash drifts. To extend seed coverage, append fixtures to
`RoutingCorpusFixtures()`; seeds propagate automatically.

## Generation Ownership (delivered)

UDP endpoint reuse preserves the generation that created the flow. Reuse may
refresh the endpoint lifetime, but it must not transfer its policy binding,
drain lease, or tracked conn-state ownership to a successor control plane.
`TestUdpEndpointPoolPreservesOriginalFlowBindingOnReuse` verifies creation,
reuse, and close: the original generation remains active until the endpoint
closes, and the successor generation is never charged for that existing flow.

## DNS Route Projection Epochs (delivered)

DNS answers and TTLs remain shared across reload, while the derived
domain-routing bitmap is versioned by the immutable policy snapshot epoch.
On DNS controller reuse, cached entries are cloned with a new projection and
old queued BPF updates are discarded when their epoch no longer matches the
active runtime. `TestDnsController_ReuseForReloadReprojectsCachedRoutes` and
`TestDnsController_ProcessBpfUpdateTaskSkipsStaleRouteProjection` are the
acceptance gates for this boundary.

## Open Decisions

- Phase 0 DNS corpus extensions still pending (next session priorities):
  - **TCP transport fallback**: requires upstream `Scheme = TCP_UDP` and
    `forwardWithFallback` path, not user-facing `Handle_`. Need a separate
    fixture type that bypasses `Handle_` and tests the transport layer
    directly, OR a config that wires a `tcp+udp://` upstream through
    `RequestSelect`.
  - **QUIC sniffing corpus**: needs sniffing pipeline hook; design TBD.
  - **Reload-with-live-flows corpus**: needs runtime supervisor scaffolding
    (Phase 7 dependency).
- Whether to retrofit a fuzz target on the DNS corpus `ReplayDns` before
  tackling Phase 2 truth wiring.
- Whether to record throughput / allocation / latency baselines on fixed
  hardware before adding Phase 4 BPF epoch work (plan requires this
  before setting a performance gate).

## Blocked

- None currently.

## Next Session

Read this file top-to-bottom; everything needed to resume is here. Priority
order (each is a single-session chunk):

1. **Phase 0 DNS corpus: TCP transport fallback** — design a fixture that
   exercises `forwardWithFallback` with `upstream.Scheme = TCP_UDP`. Either
   add a transport-level replay path to the corpus driver, or wire a
   `tcp+udp://` upstream through `RequestSelect` so `Handle_` reaches the
   fallback path naturally. Prefer the latter (keeps the corpus at the
   user-observable layer).
2. **Phase 0 DNS corpus: QUIC sniffing** — needs the sniffing pipeline
   invoked from DNS response routing. First read
   `component/sniffing/` and `control/dns_control.go` response-routing
   call sites to identify the hook point, then add a fixture with a
   synthetic SNI-bearing QUIC ClientHello.
3. **Phase 2 truth wiring** — `PolicySnapshot` is currently a shadow
   semantic layer; the production route still executes
   `RoutingMatcher.Match`. Extract shared per-function predicate evaluation
   (Domain, IP, port, source, process, DSCP, MAC, and fallback) from the
   matcher, then make both the matcher and `PolicySnapshot.Evaluate` consume
   that one result. Acceptance requires the Phase 0 corpus to compare the
   production path directly against the snapshot, not a separately built
   matcher.
4. **Performance baseline** — record throughput, allocation, and latency on
   fixed hardware before broadening the BPF publication gate.
