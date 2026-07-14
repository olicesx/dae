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
| 0. Compatibility Corpus & Observability | NOT STARTED | next focus |
| 1. Immutable Policy Snapshot | PARTIAL | types + unit tests only; no corpus equivalence yet |
| 2. Three-Valued Evaluation | PARTIAL | `truth.go` exists, not wired into routing |
| 3. Decision Adapter & Shadow | PARTIAL | `Decision` type exists, no shadow wiring |
| 4. Epoch-Scoped Kernel Plan | NOT STARTED | — |
| 5. DNS Resolver/Cache/Projection | PARTIAL | upstream/delivery split only |
| 6. Flow & Egress Bindings | PARTIAL | UDP done, TCP not started |
| 7. Runtime Supervisor | NOT STARTED | — |
| 8. Controlled Cutover | NOT STARTED | — |

## Open Decisions

- Phase 0 corpus: scope and fixture format TBD (see phase0-design.md once
  written).
- Whether to retrofit equivalence tests into already-committed Phase 1/5/6
  partial work before moving forward.

## Blocked

- None currently.
