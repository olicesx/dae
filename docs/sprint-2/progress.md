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
| 0. Compatibility Corpus & Observability | PARTIAL | routing corpus done (20 fixtures, 46 cases); DNS / TCP / UDP / QUIC / reload corpora still pending; performance baseline not yet recorded |
| 1. Immutable Policy Snapshot | ACCEPTANCE MET (userspace) | corpus-equivalent test passes for all 20 fixtures; kernel-side equivalence and fuzz tests still pending |
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

## Open Decisions

- Phase 0 sub-system corpora (DNS, transport, reload) — scope and format
  still TBD. Routing corpus pattern is the template; DNS corpus should
  cover UDP/TCP transports, stale cache hits, reject-before-cache,
  QUIC sniffing; transport corpus should cover TCP reroute on sniff,
  UDP full-cone/symmetric reuse, QUIC upgrade; reload corpus should
  cover live-flow drain.
- Whether to retrofit a fuzz target on `Replay` before tackling Phase 2.
- Whether to record throughput / allocation / latency baselines on fixed
  hardware before adding Phase 4 BPF epoch work (plan requires this
  before setting a performance gate).

## Blocked

- None currently.
