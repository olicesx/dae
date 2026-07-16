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

Carried in workspace (2026-07-14, orchestrator):
- `feat(control): add Phase 1 fuzz target + Phase 0 DNS corpus foundation`
  — Adds `control/refactor_corpus_fuzz_test.go` (Phase 1 acceptance clause
  4: fuzz tests cover aliasing and deterministic hashing; 33k execs, 0
  crashes) and `control/refactor_dns_corpus{,_fixtures,_test}.go` (Phase 0
  DNS corpus with 5 fixtures: udp_cache_miss, udp_cache_hit,
  udp_cache_stale_optimistic, tcp_udp_fallback, reject_before_cache). The
  `tcp_udp_fallback` fixture selects a named `tcp+udp://` upstream through
  `RequestSelect`, observes a failed UDP attempt, then pins successful TCP
  delivery. No production code modified.

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

## Continuation Update (2026-07-15)

This worktree now has the compatibility scaffolding required to keep the
semantic refactor non-authoritative by default. This is not a cutover claim:
the legacy matcher, legacy DNS handler, and legacy BPF publication path remain
the default execution paths.

Delivered in this continuation:

- Added the internal `DAE_SEMANTIC_REFACTOR_FEATURES` gate. Its
  `compiled-policy`, `routing-epoch`, `dns-resolver`, and
  `udp-ordered-dispatcher`, and `udp-reply-dispatcher` paths are captured per
  control-plane generation and default to disabled. Generation snapshots keep
  their enabled paths after the process-level gate owner is released.
- Kept Phase 4 decision shadowing separately opt-in through
  `DAE_PHASE4_DECISION_SHADOW_SAMPLE_EVERY`. Incomplete QUIC SNI facts now
  retain only a bounded immutable continuation and resume on the terminal
  observation; continuations expire before a reused tuple can force a stale
  comparison, and a known absent domain no longer produces a false divergence.
- Restricted staged same-port reload handoff to the `routing-epoch` gate so a
  default-gated reload follows the legacy ownership path instead of attempting
  to link two slot-zero generations.
- Extended kernel routing-epoch tests to exercise both active slots and verify
  slot attribution in conn-state and handoff records.
- Corrected the `dae_stub_ebpf` port-range ABI helper so compiled-policy
  adapter tests preserve port and source-port ranges. The regression test
  covers plan lowering, adapter reconstruction, and userspace replay.
- Added a fixed DNS corpus differential that compares legacy handling with the
  gated Resolve/delivery pipeline, including canonical response wire, errors,
  cache keys, and selected upstream/dial routes.
- Added a complete-fact decision-shadow fuzz target seeded from the routing
  corpus; its baseline verifies zero sampled divergence and errors.
- Added routing-epoch regressions covering preparation failure, publish/
  hook-flip rollback, and real eBPF packet verdicts for slot-specific domain
  projections without mixing the active slot's routing plan.
- Added a per-control-plane TCP flow registry. It records the immutable route
  and egress binding only after a successful transparent TCP dial on the final
  staged-reload owner, unregisters on relay exit, and uses entry-conditional
  deletion so delayed cleanup cannot erase a reused tuple.
- Forced abort now detaches the TCP registry atomically with ingress ownership,
  closes the bound egress, and rejects a dial that finishes after abort. The
  registry tests also cover lease handoff ownership and expected double-close
  errors.
- Added a concurrent UDP endpoint creation regression: sixteen same-key
  callers share one endpoint, perform one dial, and retain the first immutable
  `UdpFlowBinding`.
- Added a testable `runtimeSupervisor` state machine for Phase 7. It models
  one active, one prepared, and one retiring generation; publishes only an
  identity-matched prepared candidate, preserves the active generation on
  rollback, blocks a third generation while retirement holds a slot, and
  ignores stale retirement completion.
- Added a Phase 2 live-matcher differential. Predicate-group spans are now
  recorded while the legacy lowerer runs, so `PolicySnapshot.EvaluateGroups`
  reads the same compiled predicate data as `ControlPlane.Route`. Parameter
  keys within one function use legacy OR semantics, apply negation once after
  aggregation, and retain only a relevant unknown continuation. The corpus
  now covers positive full/suffix/keyword first, middle, and last-key hits.
- Bound the sampled Phase 4 decision shadow to its generation's live
  `RoutingMatcher` after userspace construction. The isolated predicate
  matcher remains only as a direct-construction fallback; live shadows keep
  domain facts unknown until observed and preserve legacy routing authority.
- Added a cross-protocol shadow corpus for TCP TLS SNI, UDP QUIC SNI, TCP/UDP
  DNS association, and known-absent UDP facts. It verifies legacy routing
  authority while the shadow preserves evidence provenance across transports.
- Added a deterministic Phase 5 DNS projection lifecycle corpus. It covers
  TTL expiry, retry scheduling after a projection failure, shared-IP ownership
  across two domains, stale retry rejection after an epoch replacement, and
  final domain-knowledge cleanup without sleeps or real BPF.
- Wired the Phase 7 supervisor through initial listener setup and every
  reload mode (default, staged, and fresh datapath): candidates stay prepared
  until ready, then publish before retirement. A reload-transition barrier
  covers BPF transfer, graceful shutdown snapshots and joins an owned
  retirement task, and fast-exit deliberately preserves the legacy immediate
  process-exit path.
- Prepared DNS listener cutover now treats upstream warmup cancellation or
  timeout as a candidate failure before reuse/start hooks run. The existing
  non-ready reload rollback keeps the old generation active; a ready listener
  reuse still succeeds after availability is confirmed.
- Added a generation-owned, fixed-worker UDP ordered ingress dispatcher behind
  `udp-ordered-dispatcher`. It preserves FIFO per `UdpFlowKey`, bounds worker
  count, yields after a finite hot-flow quantum, immediately reclaims drained
  queues, and explicitly discards queued work during retirement, abort, or
  close so ingress leases and packet buffers are released. The default path
  still uses the legacy process-wide `DefaultUdpTaskPool` unchanged.
- Added a separate generation-owned UDP reply dispatcher behind
  `udp-reply-dispatcher`. It keeps a bounded 256-reply backlog per endpoint,
  preserves FIFO delivery, drains replies accepted before normal endpoint
  close, and releases pending packet buffers on endpoint failure or dispatcher
  abort. The default per-endpoint sender remains unchanged.
- Added a gate lifecycle integration check that captures all enabled semantic
  paths into a generation value and closes both gated dispatchers through the
  real `ControlPlane.Close` path after the process-level owner is released.
- Closed the staged routing-epoch health-write window. Prepared candidates
  start with outbound-connectivity updates paused; the old generation is
  paused immediately before candidate datapath commit; the candidate publishes
  one serialized health snapshot only after supervisor publication; and a
  staged rollback restores the old generation's write ownership.

Verification rerun after the ordered-ingress and staged-connectivity updates:

- `make ebpf-sync-check`
- `make ebpf-lint`
- `make ebpf-test`
- `make ebpf`
- `go test ./... -count=1`
- `go test -tags=dae_stub_ebpf ./... -count=1`
- `go test -race ./control ./cmd -count=1`
- `go test -race ./cmd -run=TestRuntimeSupervisorConcurrentPublishRollbackAndShutdown -count=1`
- `go test -race ./cmd -run=TestRuntimeSupervisor -count=1`
- `go test -race ./cmd -run=TestReloadManagerRepeatedRetirementLifecycleReclaimsGeneration -count=1`
- `go test -race ./control -run=TestUDPReplyDispatcher -count=1`
- `go test -race ./control -run=TestSemanticRefactorFeatureGate -count=1`
- `go test -race ./control -run=TestPhase4DecisionShadowCrossProtocolCorpus -count=1`
- `go test -race ./control -run=TestPhase3DecisionShadowAllocationBudget -count=1`
- `go test ./control -run=^$ -bench=BenchmarkPhase -benchmem -count=5`
- `bash scripts/semantic-refactor-benchmark.sh -count=1`
- `bash scripts/semantic-refactor-benchmark.sh -count=20`
- `go vet ./...`
- `git diff --check`

Latest affected-path verification after the reply dispatcher and DNS fuzz
updates:

- `scripts/semantic-refactor-live-smoke.sh ./dae install/empty.dae 64`
- `scripts/semantic-refactor-live-dns-smoke.sh ./dae 8.8.8.8 64`
- `scripts/semantic-refactor-live-tcp-smoke.sh ./dae example.com 16`
- `scripts/semantic-refactor-live-local-tcp-smoke.sh ./dae 64`
- `scripts/semantic-refactor-live-local-udp-smoke.sh ./dae 64`
- `scripts/semantic-refactor-live-local-quic-smoke.sh ./dae 64`
- `scripts/semantic-refactor-live-quic-smoke.sh ./dae https://cloudflare-quic.com/ 64`
- `scripts/semantic-refactor-live-local-iperf-smoke.sh ./dae 3`
- `go test ./control -count=1`
- `go test ./control -race -count=1`
- `go test ./... -count=1`
- `go test -tags=dae_stub_ebpf ./... -count=1`
- `go test -race ./control ./cmd -count=1`
- `go vet ./...`
- `make ebpf-sync-check`
- `make ebpf-lint`
- `make ebpf-test`
- `make ebpf`
- `GOWORK=/root/dae-outbound-work/go.work go test -race ./netproxy ./protocol/tuic ./protocol/hysteria2/client` in the sibling outbound fork
- `git diff --check`

## Continuation Update (2026-07-16)

- The sibling `/root/outbound` fork is now used through the local `go.mod`
  replace so dae and the transport adapters are verified together.
- Added an optional `netproxy.PacketReceiver` boundary with idempotent packet
  release ownership. TUIC and Hysteria2 deliver complete datagrams from their
  existing shared readers; Hysteria2 registration and fallback queue handoff
  are serialized against fragment reassembly and session close.
- `UdpEndpoint` synchronously registers the receiver when the generation reply
  dispatcher is enabled. It retains the legacy blocking `ReadFrom` path for
  unsupported or compatibility-only connections and releases producer-owned
  buffers after reply dispatch completes.
- Added focused endpoint and sibling outbound tests for queued packets,
  fragment assembly, wrapper forwarding, registration handoff, close/unregister
  idempotence, and packet ownership. The full dae and sibling verification
  suites pass, including race, stub eBPF, vet, eBPF sync/lint/kernel tests,
  and eBPF generation.
- Added an internal final ControlPlane construction seam after config
  normalization and subscription/reload guards. Boundary tests exercise all
  initial/prepared/reload combinations, injected construction failure,
  canceled construction, and caller-config isolation before candidate
  installation.
- Added an isolated child-process construction harness that runs 256 mixed
  failed/canceled prepared-candidate attempts and requires every attempt to
  return no control plane while preserving the injected error contract.
- Added a Runner-level construction-failure test with all semantic features
  enabled; after the injected startup failure, a fresh owner can reacquire
  every feature gate, proving failed startup does not strand process-global
  migration state.
- Added Runner operation seams for netns execution, listener open/clone, and
  Serve, while keeping direct production implementations by default. The new
  child-process harness now runs a real fresh-datapath reload transition,
  injects candidate readiness failure, exercises rollback and recovered
  generation readiness, uses real listener open/clone/close operations, then
  terminates through the normal shutdown path. The child repeats this fresh
  rollback cycle 64 times and waits for each reload-failure completion.
- Added a shared-BPF staged-reload child case with the routing-epoch handoff
  link, candidate Serve/DNS-warmup failure, old-generation preservation, and
  normal shutdown. It verifies the candidate is built and linked once while
  no recovery generation is incorrectly published.
- Added optional `ControlPlane.Serve` lifecycle hooks, disabled by default, so
  the Runner child-process boundary can execute the real candidate Serve
  sequence and inject failure at either prepared BPF commit or DNS/runtime
  activation. Both failures return before readiness, roll back the candidate,
  preserve the old generation, and complete normal shutdown; the child also
  retains real listener open/clone/close operations.
- Construction now tracks dae netns ownership. A startup or candidate build
  failure cleans a netns created by that build, while shared-BPF reloads retain
  the active generation's netns; namespace handles and setup state are reset
  so a later same-process build can acquire fresh resources.
- Mounted bpffs in the WSL2 verification environment and completed a real
  empty-config BPF startup. The process loaded programs/maps, completed 64
  consecutive `SIGUSR2` suspend/reload cycles with candidate retirement, and
  detached hooks on termination. A second real startup after the intentional
  fast-exit residue purged the stale TC filter, rebuilt the BPF datapath, and
  reached control-plane readiness. The run used no proxy nodes, DNS traffic,
  or live application flows, so it is deployment smoke evidence rather than
  the required production soak.
- Added `scripts/semantic-refactor-live-smoke.sh`, which refuses to touch an
  existing dae deployment, mounts bpffs only for the test, runs the real
  startup/reload/fast-exit/recovery sequence, asserts stale-TC cleanup, and
  removes all resources it created. The script passed with 64 reload rounds;
  daemon RSS was `37,112 KB` at baseline and `42,012 KB` at the observed peak,
  stale-state recovery passed, and the WSL2 environment was restored to an
  unmounted, resource-free state. This is process-level local memory
  observation, not production leak evidence.
- Added `scripts/semantic-refactor-live-dns-smoke.sh`, which starts a real
  local DNS listener over BPF, sends A/AAAA wire queries through it, repeats
  A to exercise the cache, and cleans up the deployment. The script accepts a
  third `rounds` argument to repeat the A/cache-A/AAAA sequence. A 64-round
  WSL2 run passed with A=282ms, cached-A=0ms, and AAAA=278ms using 8.8.8.8 as
  a real public UDP upstream; it is stronger DNS UDP soak evidence, but not a
  long-running application-flow soak on production hardware.
- Added `scripts/semantic-refactor-live-tcp-smoke.sh`, which resolves an IPv4
  target before startup, runs real WAN-hook HTTPS requests with `--resolve`,
  and sends a reload while each request is in flight. A 16-round WSL2 run
  passed with `example.com`, with daemon fd baseline/max `64/64`, connect
  latency `168.5-1218.2ms` (avg `253.5ms`), and total latency
  `533.3-3322.3ms` (avg `1191.6ms`); a separate 32-round attempt had one
  external TLS timeout at round 30 and is retained as instability evidence
  rather than a passing soak result. The harness cleans all BPF, veth, and
  namespace state.
- Added `scripts/semantic-refactor-live-local-tcp-smoke.sh`, which creates a
  temporary server namespace and veth, serves a rate-limited HTTP payload, and
  reloads dae while each flow remains active. A 64-round WSL2 run passed with
  daemon fd baseline/max `64/64`, connect latency `0.1-0.4ms` (avg `0.1ms`),
  and total latency `6853.8-7843.1ms` (avg `7508.2ms`); cleanup removed the
  test veth, both namespaces, BPF pins, and the bpffs mount. This is
  deterministic kernel-path evidence, not production network or hardware soak
  evidence.
- Added `scripts/semantic-refactor-live-local-udp-smoke.sh`, which creates a
  delayed UDP echo server in a temporary namespace and sends each datagram
  during a reload. A 64-round WSL2 run passed with daemon fd baseline/max
  `64/64` and echo latency `250.2-250.5ms` (avg `250.3ms`); cleanup removed
  the veth, namespaces, BPF pins, and bpffs mount. This covers a deterministic
  local UDP kernel path, not public-network UDP deployment soak.
- Added `scripts/semantic-refactor-live-local-quic-smoke.sh` and its
  `scripts/semantic-refactor-quic-helper` endpoint. The helper uses the
  repository quic-go fork with self-signed TLS and datagrams; a 64-round WSL2
  veth WAN-hook run passed during reload with fd baseline/max `64/64` and
  datagram latency `250.3-251.6ms` (avg `251.0ms`). Cleanup removed the veth,
  namespaces, BPF pins, and bpffs mount. This is deterministic local QUIC
  kernel-path evidence, not public-network or production hardware soak.
- Extended `scripts/semantic-refactor-quic-helper` with an HTTP/3 client and
  added `scripts/semantic-refactor-live-quic-smoke.sh`. A 64-round WSL2
  real-BPF WAN-hook run reached public `https://cloudflare-quic.com/` during
  reload with HTTP/3 latency `356.5-3383.8ms` (avg `883.9ms`) and daemon fd
  baseline/max `64/64`; the direct helper handshake returned HTTP `200` before
  the hook test. Cleanup removed all BPF state and temporary resources. This
  is public HTTP/3 evidence for one endpoint, not arbitrary public UDP
  datagram or production hardware soak evidence.
- Added `scripts/semantic-refactor-live-public-udp-smoke.sh` as a direct
  application-UDP probe. On this WSL2 host it reproduces the remaining gap:
  host `dig @8.8.8.8` and the DNS listener smoke succeed, but the same DNS
  request sent through the real-BPF WAN hook is recaptured and the daemon's
  direct forwarder times out. The daemon log reports
  `DNS ingress fast path failed` with `read udp ... i/o timeout`. The host's
  marked UDP socket and the daemon's DNS socket both report `SO_MARK=0x100`
  outside the hook. The local daemon uses veth fallback because the kernel
  returns `operation not supported` for Netkit creation; the documented Netkit
  `scrub=NONE` path is therefore not available in this environment. Additional
  BPF tracing shows the cgroup cookie map records dae's PID in a different PID
  namespace from the userspace `os.Getpid()` constant, so the control-plane
  self-capture check cannot be treated as proven here. This probe remains a
  supported-environment acceptance test, not a claimed WSL2 pass.
- Added `scripts/semantic-refactor-live-local-iperf-smoke.sh`, which runs
  deterministic TCP and UDP throughput transfers through real BPF WAN hooks
  over a temporary veth while reloading dae. Its default 3-second WSL2 run
  uses unlimited UDP mode and reported TCP receive `51.23 Gbit/s`, UDP receive
  `3.01 Gbit/s` from `3.04 Gbit/s` sent, `0.900%` loss, and `0.001 ms` jitter;
  daemon fd baseline/max stayed at `64/64`. The script accepts an optional
  third argument to impose a controlled UDP target rate, and cleanup removed
  the veth, namespaces, BPF pins, and bpffs mount. This establishes a
  repeatable local kernel-path throughput baseline, not a production hardware
  performance gate.
- Extended `.github/workflows/kernel-test.yml` so the supported 6.6 and 6.12
  LVH matrix now runs `make ebpf-sync-check`, `make ebpf-lint`, and the real-BPF
  startup/reload/stale-state recovery smoke before its existing WAN TCP/UDP
  checks. The workflow is an executable cross-kernel acceptance gate; its CI
  results are not available for this branch yet and are not claimed here. As
  background evidence, upstream run
  `29379885993` ([kernel-test run](https://github.com/daeuniverse/dae/actions/runs/29379885993))
  passed both the 6.6 and 6.12 jobs, including the existing IPv4/IPv6 UDP and
  port-conflict checks; that run predates the new reload smoke step.
- Extended the transport-owned packet receiver through Shadowsocks,
  Shadowsocks-Stream, Shadowsocks 2022, and SOCKS5 UDP wrappers. Each wrapper
  decodes its own framing before handing a complete payload and source address
  to dae, forwards transport errors, and preserves raw/mapped buffer ownership
  on rejection.
  The transport-only Shadowsocks-Stream wrapper keeps its invalid source
  address semantics. A pool alias guard also prevents Shadowsocks AES-GCM
  decryption output from overlapping the caller-owned encrypted packet.
- Extended the deterministic Phase 5 DNS replay to 256 rounds and 128
  mutations per corpus case, including an NXDOMAIN delivery/non-cache case. A
  60-second `FuzzPhase5DnsResolvePipelineEquivalence` run completed with 7,133
  executions and zero legacy/pipeline divergences after fixing the fuzz
  observer's stale-refresh delivery boundary.

Remaining acceptance blockers are deliberate and must remain visible:

- Fixed WSL2 microbenchmarks and a deterministic real-BPF veth throughput
  baseline are recorded, but production-like throughput, end-to-end latency,
  and long-running allocation measurements on supported hardware are still
  absent, so no release performance gate can be set.
- Decision shadowing now has cross-protocol corpus coverage and local CPU and
  allocation guards; a same-process budget keeps shadow evaluation within 4x
  of the legacy matcher and rejects evaluations above 24 allocs/op. Production
  hardware and end-to-end CPU evidence are still required before cutover.
- Epoch publication now has map-level, rollback, and packet-level domain
  projection coverage; evidence across the supported kernel range is still
  absent.
- Phase 6 now has feature-gated fixed-worker replacements for generic ordered
  UDP ingress and endpoint reply senders, plus grouped transport-lifecycle
  watchers that are canceled and joined on endpoint-pool reset. The sibling
  outbound fork now exposes an optional transport-owned packet-delivery API;
  TUIC and Hysteria2 use their existing shared readers to deliver complete
  datagrams, and dae synchronously registers those receivers so supported
  endpoints do not start a blocking `ReadFrom` loop. Linux direct UDP sockets
  now share one process-level epoll reader; non-Linux builds, manually
  constructed sockets, and protocols without a shared reader retain the
  compatibility path. Metadata-sensitive UDP ingress retains its route-scope
  lookup by design.
  Transport-owned delivery now also survives the supported stream-wrapper
  layers.
  Phase 7 now serializes reload ownership, graceful shutdown, and staged
  health-map ownership. Targeted BPF cutover failures, concurrent supervisor
  transitions, repeated generation-slot cleanup, reload-manager retirement
  cleanup, child-process fresh/staged/live-Serve rollback, and real startup
  cleanup after a missing BPF pin root are covered; external DNS/UDP/QUIC flow
  soak, long-running allocation, and production leak evidence still remain before
  promotion. WSL2 now also has repeatable real-empty-config BPF reload/recovery
  local DNS listener/cache smoke, bounded external plus deterministic local
  WAN-hook TCP/UDP/QUIC reload soak runs (64 rounds each), a public HTTP/3
  reload soak, RSS observation across 64 real-BPF reloads, and a local
  TCP/UDP iperf3 throughput baseline.
- Bounded WAN-hook TCP and deterministic local-veth TCP/UDP/QUIC reload soak
  succeeds in WSL2; the 64-round DNS smoke reaches public `8.8.8.8:53/UDP`,
  and the 64-round public HTTP/3 smoke reaches `cloudflare-quic.com` through
  the real BPF WAN hook. This establishes public DNS UDP and one public QUIC
  HTTP/3 endpoint, but the direct application-UDP probe still fails on the
  WSL2 Netkit creation is unsupported and the BPF cgroup PID identity does not
  match the userspace PID constant, despite the daemon DNS socket retaining
  `SO_MARK=0x100`. Arbitrary public UDP datagram coverage and production
  hardware soak therefore remain open; the one failed 32-round external TCP
  attempt also prevents claiming a long external TCP soak here.

## Phase Status (vs plan)

| Phase | Status | Notes |
|---|---|---|
| 0. Compatibility Corpus & Observability | PARTIAL | routing/DNS/TLS/QUIC/reload corpus and sampled observability foundations exist; routing-corpus and DNS cache-hit microbenchmarks plus a deterministic real-BPF veth throughput baseline cover the expanded local surface, but production throughput/latency evidence is still absent |
| 1. Immutable Policy Snapshot | IMPLEMENTED, NOT PROMOTED | clone/hash/epoch isolation, compiler differential checks, and fuzzing exist; promotion still depends on Phase 0 performance evidence and full required verification at cutover time |
| 2. Three-Valued Evaluation | IMPLEMENTED, SHADOW-ONLY | function-level key OR/negation, fact-aware evaluation, immutable continuations, and live-matcher corpus differential exist; legacy routing remains authoritative |
| 3. Decision Adapter & Shadow | PARTIAL, SHADOW-ONLY | sampled bounded evidence and continuation resumption now use the live matcher when a control plane is constructed; local relative CPU and allocation budgets are guarded, while production evidence remains |
| 4. Epoch-Scoped Kernel Plan | PARTIAL, FEATURE-GATED | two-slot stage/publish/rollback, packet-level slot/domain-projection isolation, and BPF attribution tests exist; cross-kernel evidence remains |
| 5. DNS Resolver/Cache/Projection | PARTIAL, FEATURE-GATED | resolver/delivery split, projection epochs, fixed-corpus legacy-vs-resolver differential including A/AAAA cache hits and NXDOMAIN delivery, deterministic TTL/retry/shared-IP/cross-epoch lifecycle coverage, 256-round replay, and 128 mutations per corpus case exist; broader soak and performance evidence remain |
| 6. Flow & Egress Bindings | PARTIAL, FEATURE-GATED | UDP endpoint bindings and creation-race coverage, a per-generation TCP registry, fixed-worker generic ordered ingress/reply dispatchers, reset-safe grouped transport lifecycle watchers, and transport-owned packet delivery through TUIC/Hysteria2, Linux direct sockets, plus Shadowsocks/Stream/Shadowsocks 2022/SOCKS5 wrappers exist; unsupported-protocol receive loops and metadata-sensitive ingress remain acceptance blockers |
| 7. Runtime Supervisor | PARTIAL | initial, default, staged, and fresh reload transitions use active/prepared/retiring ownership; graceful shutdown joins retirement and carries generation cancellation, staged health writes have explicit ownership and rollback, candidate and failed-startup netns cleanup is idempotent, targeted BPF/concurrent/repeated/failure-matrix/fuzz plus isolated child-process lifecycle tests pass, and WSL2 real-BPF empty-config reload/recovery plus bounded external TCP/DNS, 64-round local-veth TCP/UDP/QUIC flow, public HTTP/3 reload, RSS observation, and iperf3 throughput smoke passes; arbitrary public UDP datagram, production leak evidence, and cross-kernel execution remain |
| 8. Controlled Cutover | IN PROGRESS | internal feature gates default to legacy behavior and generation snapshots survive owner release; enabled-path integration, soak, performance, and release-cycle rollback evidence remain |

## Phase 0 routing corpus (delivered)

Files:
- `control/refactor_corpus.go` — `CorpusFixture`, `CorpusInput`, `CorpusExpected`,
  `Replay(t, matcher, fixture)` driver. MAC and process-name conversion
  helpers mirror `ControlPlane.Route` semantics.
- `control/refactor_corpus_fixtures.go` — 24 fixtures covering every routing
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

## Phase 0 DNS corpus (legacy baseline and Phase 5 differential)

Files:
- `control/refactor_dns_corpus_support_test.go` — `DnsCorpusFixture`, `DnsCorpusCase`,
  `DnsCorpusExpected`, `ReplayDns(t, fixture)` driver. Mirrors routing corpus
  pattern: builds a fresh `DnsController` from the fixture's `*config.Dns`,
  installs best-dialer chooser and forwarder factory, then for each case
  optionally runs `PreState` (e.g. cache warm) before invoking
  `HandleWithResponseWriter_` and asserting the captured response shape.
- `control/refactor_dns_corpus_fixtures_test.go` — 7 fixtures:
  - `udp_cache_miss` — cold cache UDP query forwards upstream and returns the
    canned answer (IP encodes dial target).
  - `udp_cache_hit` — warm cache serves the cached IP without contacting the
    factory (factory IP differs from cached IP for clear regression signal).
  - `udp_cache_hit_aaaa` — warm AAAA cache serves a cached IPv6 answer and
    pins the qtype-specific cache key and response wire.
  - `negative_upstream_response` — NXDOMAIN is delivered with its rcode and
    wire preserved, but a repeated query forwards again instead of reusing a
    positive address cache entry.
  - `udp_cache_stale_optimistic` — stale-but-not-expired cache serves the
    cached IP; the background refresh path is not externally observable.
  - `tcp_udp_fallback` — named `tcp+udp://` upstream first fails UDP, then
    succeeds over TCP through the user-observable request and delivery path.
  - `reject_before_cache` — DNS `qname(full)` reject rule short-circuits even
    when a warm cache entry exists; documents the `Handle_` invariant.
- `control/refactor_dns_corpus_test.go` — `TestPhase0DnsCorpus_LegacyBaseline`
  pins current behaviour.

Helpers reused from existing test infrastructure: `stubDnsForwarder`,
`setScopedBestDialerChooser`, `dnsAResponseMsg`, `dnsAnswerIPv4`, and
`dnsAnswerIPv6`; `dnsAAAAResponseMsg` provides the fixed IPv6 cache fixture.

## Phase 0 Performance Baseline (recorded)

`control/phase0_performance_bench_test.go` provides repeatable CPU and
allocation measurements for the legacy routing matcher, the full routing
corpus matrix, Phase 3 shadow evaluation, and a legacy-vs-resolver DNS cache
hit. `scripts/semantic-refactor-benchmark.sh` records the environment and
runs the same benchmark. The command used for this snapshot was:

```text
go test ./control -run=^$ -bench=BenchmarkPhase -benchmem -count=5
```

The fixed test environment was WSL2 on 2026-07-15: Linux 6.18.33.2,
`x86_64`, 12 visible vCPUs, Intel Core i7-14650HX, and 32,758,400 kB reported
memory. The benchmark ran with `GOMAXPROCS=12`.

| Path | Median ns/op | B/op | allocs/op | Five-run range (ns/op) |
|---|---:|---:|---:|---:|
| Legacy routing match | 1,578 | 528 | 5 | 1,545-1,658 |
| Shadow TCP/TLS evaluation | 2,375 | 793 | 16 | 2,320-2,452 |
| Shadow UDP/QUIC evaluation | 2,342 | 793 | 16 | 2,132-2,456 |

The latest three-run sample on 2026-07-16 produced the following median. It
was collected with `bash scripts/semantic-refactor-benchmark.sh -count=3` on
the same WSL2 host.

| Path | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| Legacy routing match | 2,021 | 528 | 5 |
| Legacy routing corpus matrix | 2,816 | 483 | 4 |
| Shadow TCP/TLS evaluation | 3,158 | 793 | 16 |
| Shadow UDP/QUIC evaluation | 6,068 | 793 | 16 |
| Legacy DNS cache hit | 3,842 | 960 | 22 |
| Resolver-pipeline DNS cache hit | 5,375 | 1,192 | 25 |

A 20-run repeated sample on the same host completed on 2026-07-16 with the
following ranges. B/op and allocs/op were invariant across all 20 runs:

| Path | 20-run ns/op range | B/op | allocs/op |
|---|---:|---:|---:|
| Legacy routing match | 1,792-2,197 | 528 | 5 |
| Legacy routing corpus matrix | 2,699-3,350 | 483 | 4 |
| Shadow TCP/TLS evaluation | 2,588-3,462 | 793 | 16 |
| Shadow UDP/QUIC evaluation | 2,507-3,222 | 793 | 16 |
| Legacy DNS cache hit | 1,376-1,782 | 960 | 22 |
| Resolver-pipeline DNS cache hit | 1,516-1,989 | 1,192 | 25 |

These are process-local microbenchmarks, not end-to-end packet throughput,
latency, or allocation gates. Production hardware, kernel, network path, and
long-running soak measurements are still required before enabling an
authoritative cutover or setting a release threshold. The resolver delivery
path now reuses its already-unpacked response for writer-based transports and
shares immutable cached wire bytes between result copies, reducing the
measured resolver path to 25 allocations/op and 1,192 B/op. It remains
slightly slower than the legacy cache-hit path in this local sample, so this is
improvement evidence but not a promotion signal.

`TestPhase3DecisionShadowAllocationBudget` enforces a local upper bound of 24
allocations per shadow evaluation. The bound is intentionally wider than the
recorded 16 allocations/op to catch unbounded regressions without pretending
to be a cross-machine CPU or release budget.

`TestPhase3DecisionShadowCPUBudget` measures TCP/TLS and UDP/QUIC shadow
evaluation against the legacy matcher in the same process and requires each
variant to stay within four times the legacy `ns/op`. This is a repeatable local
regression guard, not a fixed-hardware or end-to-end release threshold.

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

## TCP Flow Registry (delivered)

`TcpFlowKey` indexes each transparent TCP relay by its converged ingress
tuple, while a second ingress index aligns it with the accepted connection
lease. The entry stores the final `TcpFlowBinding` only after `routeDial`
succeeds; DNS fast-path and public `RouteDialTcp` calls do not create entries.
Normal relay teardown removes both indexes. Forced retirement detaches entries
under the same ownership lock used for incoming connections, then closes the
bound egress. `TestTCPFlowRegistryFollowsIncomingConnectionLeaseOwnership` and
the abort/delayed-dial tests cover staged ownership, tuple reuse, cleanup, and
late registration rejection.

`TestUdpEndpointPoolGetOrCreate_ConcurrentSameKeyDialsOnceAndPreservesInitialBinding`
adds endpoint-creation-race coverage without changing the UDP transport model:
sixteen concurrent same-key calls produce one dial, one endpoint, and its
original `UdpFlowBinding`.

`TestHandlePkt_DscpControlPlaneRoutingReusesEndpointForSameFlow` mutates a
non-key routing field (`Must`) on a later packet and verifies that ordinary
ingress keeps the original endpoint binding and dialer. Metadata that is part
of the route scope still creates a distinct endpoint, as covered by the paired
DSCP separation test.

## Transport-Owned UDP Delivery (feature-gated)

The sibling `/root/outbound` fork adds `netproxy.PacketReceiver` and an
idempotent `ReceivedPacket.Release` ownership boundary. TUIC's shared QUIC
reader and Hysteria2's UDP session manager implement it; `FakeNetPacketConn`
forwards the optional interface through its net compatibility wrapper.
`UdpEndpoint` registers the receiver synchronously whenever the generation-owned
reply dispatcher is enabled. Accepted packets retain their producer-owned
storage until the reply task completes, while registration failure falls back
to the legacy blocking `ReadFrom` loop. Transport-owned callbacks submit to the
bounded reply queue without blocking: a full endpoint queue releases only the
current packet and keeps its reader registered, while a closed dispatcher
causes unregister and endpoint retirement.

`TestUdpEndpointStart_UsesTransportOwnedPacketReceiver` verifies that the dae
endpoint does not call `ReadFrom`, forwards the reply through the fixed worker
dispatcher, and unregisters exactly once during close. The outbound tests cover
queued delivery, TUIC fragment assembly, Hysteria2 session-manager delivery,
Linux direct-socket epoll multiplexing, wrapper forwarding, and idempotent
packet release. Other protocols without a shared reader retain the explicit
compatibility fallback before Phase 6 can be promoted.

## UDP Ordered Ingress Dispatcher (feature-gated)

`udp-ordered-dispatcher` creates a dispatcher per `ControlPlane` generation;
it never changes or resets `DefaultUdpTaskPool`. The dispatcher uses at most
`min(GOMAXPROCS, 8)` workers, serializes one `UdpFlowKey` at a time, requeues a
hot key after a finite quantum, and removes a queue immediately when it drains.
Accepted work runs exactly once or invokes its discard callback exactly once.
This lets `StopRoutingEpochExecution`, `AbortConnections`, and `Close` release
queued ingress admission leases instead of waiting behind canceled workers.

`udp_ordered_dispatcher_test.go` covers high-cardinality fixed worker count,
FIFO, independent-flow concurrency, hot-flow fairness, reset and close
semantics, submit/close races, old/new generation isolation, and all three
control-plane shutdown paths. DNS, SIP/RTP, STUN, endpoint receive loops, and
the gated reply dispatcher remain separate from this ingress path.

## UDP Reply Dispatcher (feature-gated)

`udp-reply-dispatcher` is a separate dispatcher because reply delivery has a
different ownership contract from ingress admission. Each endpoint retains a
bounded 256-item queue and one active worker at a time, while independent
endpoints can run concurrently. Normal `ReadFrom` exit closes endpoint input
and waits for accepted replies to drain; handler failure, endpoint abort, and
global dispatcher close release queued packet buffers exactly once. The
feature is captured by the creating control-plane generation, so an endpoint
keeps its reply worker through reload drain. The synchronous per-endpoint
`ReadFrom` loop remains until outbound exposes a transport-level readiness or
demultiplexing API.

`udp_reply_dispatcher_test.go` covers FIFO, independent-endpoint concurrency,
bounded backpressure, normal drain, endpoint abort, and global close. Endpoint
integration tests cover gated read-loop delivery, normal endpoint close, and
race-safe buffer ownership. A rejected dispatcher submission retains buffer
ownership with the read loop; `TestUdpEndpointSubmitReplyRejectedReleasesBufferOnce`
guards this contract so a close race cannot return a pooled buffer twice.

UDP endpoints that expose outbound's optional `TransportLifecycle` signal are
indexed by the shared terminal channel rather than watched one goroutine per
endpoint. Empty buckets are canceled and removed, and `UdpEndpointPool.Reset`
waits for any remaining watcher to exit before returning. The lifecycle tests
cover terminal retirement, shared transport buckets, reset with an open
transport, bucket recreation, and concurrent reset/registration under the race
detector. This handles transport death and reload cleanup; it does not provide
packet readiness or demultiplexing for the blocking `ReadFrom` contract.

## Production Matcher Differential (delivered)

The legacy `RoutingMatcher` now records immutable compiled-match spans at the
same parser boundary used by the normalized policy program. The snapshot
evaluator accepts a live-matcher resolver for those spans, rather than relying
on a per-predicate test matcher. Key groups inside one function use the legacy
OR boundary, then a single function-level negation; strong-Kleene
short-circuit rules retain only a still-relevant unknown continuation.

`TestPhase2ProductionMatcherSnapshotCorpusDifferential` compares actual
`ControlPlane.Route` output with `PolicySnapshot.EvaluateGroups` for both the
normalized-program and compiled-policy lowerers. The positive multi-key domain
fixture exercises full, suffix, keyword, and fallback outcomes.

## Runtime Supervisor Integration (delivered, not promoted)

`runtimeSupervisor` owns a concrete generation tuple
`{ControlPlane, Listener, cancel, Config}` in a mutex-protected
active/prepared/retiring state machine. `Runner.Run` registers the initial
listener synchronously, prepares default/staged/fresh candidates without
replacing the live tuple, publishes only after readiness, and reports exact
retirement completion. A transition mutex prevents shutdown from racing BPF
transfer; graceful shutdown freezes the supervisor and joins the matching
retirement worker before generic cleanup. Fast exit intentionally follows the
prior current-plus-pending-handoff process-exit behavior.

The implementation remains non-promoted: its failure matrix and process-level
soak evidence are incomplete, and legacy routing remains authoritative.

`TestRuntimeSupervisorConcurrentPublishRollbackAndShutdown` runs repeated
publish-versus-rollback races plus a publish-versus-shutdown race. It asserts
that exactly one ownership transition wins, shutdown leaves no managed
generation, and a published retirement can be completed before the next
candidate is installed.

Candidate cleanup is now owned by an idempotent `runtimeGeneration.cleanup`
operation. Staged and fresh rollback paths use it after their datapath-specific
undo steps, so readiness failure, publish failure, and repeated rollback cannot
cancel or close the same candidate twice. `TestRuntimeGenerationCleanupIsIdempotent`
and `TestRollbackStagedHandoffCleansPreparedGenerationOnce` pin this ownership
contract.

## Controlled Gate Lifecycle (delivered, not promoted)

`TestSemanticRefactorFeatureGateGenerationSnapshotSurvivesOwnerDisable` enables
all internal migration paths, captures the generation feature value, releases
the process-level owner, and verifies the global gate is disabled while the
captured generation still enables DNS Resolve/delivery plus both UDP dispatchers.
The test then closes the generation through `ControlPlane.Close`, which joins
both generation-owned dispatchers. This proves gate ownership and worker
lifetime isolation; it does not make any gated path authoritative or replace
the required enabled-path soak.

`TestRuntimeSupervisorRepeatedLifecycleReleasesGenerationSlots` repeats
rollback, publish, retirement completion, and final shutdown for 256 candidate
generations. Every iteration asserts that only the active generation remains
owned, which catches stale prepared/retiring references without claiming a
process-level soak.

`TestReloadManagerRepeatedRetirementLifecycleReclaimsGeneration` exercises the
actual reload-manager retirement worker for 64 generations. Each iteration
publishes a candidate, drains/closes the old `ControlPlane`, cancels its
context, releases supervisor retirement ownership, and clears the pending
retirement channel. The test uses the real manager/control-plane call boundary
but remains a bounded unit test rather than a long-running process soak.

The supervisor/reload matrix was repeated 20 times and the affected control
plane/DNS/epoch matrix 10 times on WSL2 without failures. These runs strengthen
local evidence only; they do not replace process-level deployment soak or
cross-kernel verification.

## Staged Connectivity Ownership (delivered)

During a shared-BPF routing-epoch handoff, a prepared candidate does not write
the outbound connectivity map. The active generation is paused immediately
before candidate serving; after `runtimeSupervisor.publishPrepared`, the
candidate writes a serialized current health snapshot and the old generation
stays paused until retirement. `rollbackStagedReloadHandoff` restores the old
owner on candidate readiness or publication failure.

`TestPreparedConnectivityHandoffSuppressesStaleWritesAndRestoresRollbackOwner`
checks the initial candidate suppression, cutover pause, rollback restoration,
post-publication candidate ownership, and final retirement guard against the
shared BPF map.

Prepared DNS listener cutover now requires an available upstream before it
runs reuse or start hooks. A timeout or canceled warmup returns from `Serve`
before readiness, so the existing prepared-candidate rollback path retains the
old generation. A confirmed available listener reuse still transfers ownership
without starting a duplicate listener.

## Live Decision Shadow (delivered)

When Phase 4 sampling is enabled, control-plane construction binds the
generation's immutable live `RoutingMatcher` to the shadow. Complete facts use
that matcher for predicate groups; missing domain evidence remains Unknown and
resumes through the stored immutable continuation. Directly constructed test
shadows retain an isolated predicate-matcher fallback only when no live matcher
is bound.

## Packet-Level Routing Epoch Coverage (delivered, not promoted)

The kernel test harness now exercises real TC packet verdicts for two routing
epoch slots with the same destination address. Slot zero's domain projection
selects one proxy outbound; slot one carries an empty projection and selects a
different fallback outbound. The checks also assert conn-state and handoff
slot attribution for the redirecting path. This proves the active selector and
domain projection are read from the same slot in the tested kernel.

`make ebpf-test` passes this coverage on the current WSL2 kernel. The CI
kernel-test matrix currently exercises 6.6 and 6.12 (6.1 is explicitly
dropped because of BPF verifier limitations); broader supported-kernel and
long-running packet soak evidence remain promotion gates.

## DNS Route Projection Epochs (delivered)

DNS answers and TTLs remain shared across reload, while the derived
domain-routing bitmap is versioned by the immutable policy snapshot epoch.
On DNS controller reuse, cached entries are cloned with a new projection and
old queued BPF updates are discarded when their epoch no longer matches the
active runtime. `TestDnsController_ReuseForReloadReprojectsCachedRoutes` and
`TestDnsController_ProcessBpfUpdateTaskSkipsStaleRouteProjection` are the
acceptance gates for this boundary.

`TestPhase5DnsProjectionLifecycleCorpusTTLRetrySharedIPAcrossEpoch` composes
the previously separate lifecycle guarantees with a fixed clock: an epoch-one
failed retry is discarded after epoch two takes ownership, an expired owner
does not erase another domain sharing its IP, and the last owner clears the
derived knowledge.

`FuzzPhase5DnsResolvePipelineEquivalence` mutates bounded DNS names, IDs, and
query types from the fixed corpus and compares legacy versus resolver/delivery
observations. Its stale-cache fixture waits for the explicitly asynchronous
refresh route event before comparing delivery side effects, while all other
cases retain an immediate observation boundary. A 60-second local run covered
7,133 executions with zero response, cache-key, or delivery-route divergences.

`TestPhase5DnsResolvePipelineLongReplay` repeats every fixed fixture through
both handler modes for 256 rounds (1,792 legacy/pipeline fixture comparisons).
Each fresh
controller comparison includes canonical response wire, error outcome, cache
ownership keys, and sorted delivery routes; the test remains deterministic and
does not make the gated pipeline authoritative.

`TestPhase5DnsResolvePipelineDeterministicMutationMatrix` adds 128 deterministic
name, query-type, and request-ID mutations per corpus case and compares
the legacy and split pipelines at the same request boundary. This expands
compatibility evidence without changing production routing or cache state.

The policy snapshot fuzz target passed the existing 8-second local run. The
complete-fact decision shadow fuzz target passed a 60-second run with 8,629
executions, and the DNS pipeline target passed a 60-second run with 7,133
executions. All runs produced no crashes or compatibility divergences.

## Runtime Supervisor Failure Boundary (delivered, not promoted)

Reload transitions now use an explicit barrier shared with graceful shutdown.
Shutdown freezes new transitions, joins the active retirement worker, and only
then transfers active, prepared, and retiring generations to the shutdown
owner. Retirement completion is generation-conditional, so a canceled worker
cannot release a newer generation's slot. The reload-manager tests cover
transition blocking, worker cancellation and join, prepared-candidate
rollback, unclaimed retirement cleanup, repeated retirement lifecycle, and
race-tested shutdown.

The full Go suite, stub-eBPF suite, `go vet`, control/cmd race suite,
`make ebpf-sync-check`, `make ebpf-lint`, and `make ebpf-test` pass on the
current WSL2 environment. The latest three-run local Phase benchmark records
legacy routing at 1.8-2.1 us/op and 528 B/op, while sampled decision shadow
evaluation ranges from 2.8-6.2 us/op and stays at 793 B/op; these measurements
are local baselines only and do not establish a production performance gate.

Graceful shutdown now carries both old and current generation cancel functions
through the supervisor handoff; fast-exit keeps the historical immediate-exit
behavior. Concurrent generation cleanup is verified to execute once, and
`TestRuntimeSupervisorFailureMatrixCleansEveryGenerationOnce` executes 1,024
publish/rollback generations and requires every candidate, retired generation,
and final active generation to be cleaned exactly once. The unresolved-owner
matrix also verifies that a prepared candidate is transferred for shutdown
cleanup and cannot be published or rolled back after closure.
`FuzzRuntimeSupervisorOperations` exercised about 101k generated operation
sequences locally without leaving aliased or closed-supervisor ownership. These
checks strengthen the in-process lifecycle boundary but are not deployment
soak or leak evidence.

`TestRuntimeSupervisorProcessBoundary` launches the actual cmd test binary as a
separate child process and runs `TestRuntimeSupervisorProcessHelper` through
4,096 mixed readiness-failure, prepared-rollback, publish-retire, and shutdown
ownership transitions. The child verifies exactly-once cleanup for every
generation before reporting success. `TestRunnerFreshReloadFailureProcessBoundary`
repeats a real-listener fresh rollback 64 times without sleeping and checks
that the child process's `/proc/self/fd` count returns to its pre-run baseline
after shutdown. `TestRunnerLiveStageFailureProcessBoundary` invokes the real
candidate `ControlPlane.Serve` path and injects failure at prepared BPF commit and
DNS/runtime activation. These tests close the process-level lifecycle boundary;
they do not replace a long-running dae deployment with real kernel BPF objects,
production DNS, and live flows.

## Open Decisions

- Whether to extend the local microbench baseline with production-like packet
  throughput, end-to-end latency, and long-running allocation measurements on
  supported deployment hardware before setting a performance gate.

## Blocked

- None currently.

## Next Session

Read this file top-to-bottom; everything needed to resume is here. Priority
order (each is a single-session chunk):

1. **Phase 6 receive topology** — assess metadata-sensitive ingress and
   protocols without a shared transport reader.
   TUIC/Hysteria2 and the supported Shadowsocks/Stream/Shadowsocks 2022/SOCKS5 wrappers now
   replace their per-endpoint UDP `ReadFrom` loops without deadline polling;
   Linux direct sockets use a shared epoll reader, while unsupported protocols
   retain the compatibility fallback.
2. **Phase 7 failure matrix** — extend the Runner-level failure harness to
   drain/reclaim and long-running leak observation on a deployment with live
   BPF objects, DNS, and flows. The child harness now covers fresh and
   shared-BPF rollback ordering, real listener resource cleanup, and failure
   injection inside the real candidate Serve sequence. The live smoke script
   now covers real BPF reload and stale-state recovery; the DNS smoke script
   covers A/AAAA and repeated cache hits, and the TCP smoke script covers
   bounded external TCP and 64-round local-veth WAN-hook TCP/UDP/QUIC requests
   during reload, while public UDP/QUIC flow soak remains outstanding. The
   real-BPF smoke also records daemon RSS across 64 reloads.
3. **Phase 5 compatibility expansion** — broaden the fixed DNS corpus and run
  longer mutation/soak coverage beyond the deterministic 256-round replay
  around resolver delivery and projection; the current matrix uses 128
  deterministic mutations per corpus case.
4. **Performance baseline** — repeat the local iperf3 throughput harness and
   extend the benchmark with end-to-end latency and long-running allocation
   measurements on supported deployment hardware before broadening the BPF
   publication gate.
5. **Cross-kernel gate** — run the updated kernel-test workflow on the 6.6 and
   6.12 LVH images and retain the real-BPF reload plus WAN TCP/UDP results as
   the supported-kernel evidence set.
