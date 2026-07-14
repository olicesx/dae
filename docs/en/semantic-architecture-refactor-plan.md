# Semantic Architecture Refactor Plan

## Objective

Evolve dae without changing observable routing, DNS, transport, or reload
semantics. The refactor must preserve the kernel direct path and progressively
replace implicit cross-component state with explicit immutable policy snapshots,
flow bindings, and epoch-scoped runtime resources.

No phase may become authoritative until its compatibility checks pass. The
legacy implementation remains the behavioral oracle during every migration.

## Non-Goals

- Do not change the configuration language, defaults, rule ordering, or
  reserved outbound meanings.
- Do not move all routing into userspace or eBPF.
- Do not introduce a new user-facing configuration switch to compensate for a
  compatibility gap.
- Do not retire a legacy path before the replacement has an operational
  rollback path.

## Semantic Contract

For an identical ordered sequence of input facts, the new and legacy paths must
produce the same observable result. Input facts include the flow tuple,
metadata, domain evidence, DNS answer, dialer health changes, time, and reload
events. Observable results include direct/proxy/block disposition, outbound,
mark, must flag, dial target, selected address family, DNS wire response, and
flow lifetime transition.

Established flows retain their existing binding unless the legacy behavior
would rebind them because of a transport failure, timeout, sniffing upgrade, or
an explicit invalidation policy. Health changes affect admission for new flows,
not successful existing flows.

## Phases

### 0. Compatibility Corpus and Observability

Create deterministic routing, DNS, TCP, UDP, QUIC, and reload traces. Record
legacy outputs as golden fixtures and add sampled, low-cardinality counters for
handoffs, decisions per flow, endpoint probes, DNS projection lag, and reload
drain duration.

Acceptance:

- Every routing function, boolean combination, priority position, mark, must
  rule, fallback, and reserved outbound has fixture coverage.
- DNS UDP/TCP, stale cache, reject-before-cache, QUIC sniffing, full-cone and
  symmetric UDP flows, and reload-with-live-flows have replay coverage.
- Metrics are disabled or sampled by default and cannot change a decision.
- Throughput, allocation rate, and latency baselines are recorded on fixed
  hardware before a performance gate is set.

### 1. Immutable Policy Snapshot

Introduce an immutable `routing.PolicySnapshot` over the existing normalized
program. It has a monotonic epoch, a stable semantic hash, and clone-only
access to the normalized program. It must not own BPF objects, sockets, mutable
dialers, or a control plane pointer.

Acceptance:

- Snapshot construction does not retain mutable caller-owned rules.
- The snapshot hash changes for any policy-content change but not for an epoch
  change.
- Lowering a snapshot produces the same legacy kernel and userspace plans.
- Unit tests and fuzz tests cover aliasing and deterministic hashing.

### 2. Three-Valued Evaluation and Continuations

Model each predicate as true, false, or unknown. Unknown is used when a fact,
such as SNI, has not arrived. A rule can be terminal only when every earlier
rule is false and the selected rule is true. A negated unknown remains unknown.
Continuations resume from the earliest unknown rule in the immutable snapshot.

Acceptance:

- Truth-table tests cover AND, OR, and NOT.
- An earlier unknown prevents a later true rule from becoming terminal.
- Complete facts have identical results to the legacy matcher for the complete
  compatibility corpus.
- Continuations contain only an epoch and stable program location, never a
  mutable control plane reference.

### 3. Decision Adapter and Shadow Evaluation

Introduce a `Decision` adapter containing policy epoch, rule or continuation
identifier, outbound group, mark, must flag, evidence provenance, and binding
profile. Initially compute it in shadow mode while the legacy result remains
authoritative.

Acceptance:

- A policy-terminal proxy decision may still require userspace forwarding;
  policy resolution and execution resolution remain separate states.
- Golden traces and fuzzing report zero decision differences.
- Sampled production differences retain sufficient input evidence for replay.
- Shadow evaluation has a bounded allocation and CPU budget.

### 4. Epoch-Scoped Kernel Plan

Compile every routing map, LPM trie, and domain projection into an inactive BPF
epoch. Publish an epoch only after all of its maps are ready. Keep the previous
epoch readable until its leases drain, and rollback by switching the active
epoch rather than rebuilding maps in place.

Acceptance:

- No packet can observe a new routing plan with an old domain projection.
- Failed preparation leaves the active epoch unchanged.
- Generated Go bindings, eBPF synchronization, lint, verifier, and kernel
  tests pass for the supported kernel range.
- Every BPF routing handoff identifies the policy epoch that produced it.

### 5. DNS Resolver, Cache, and Knowledge Projection

Split DNS into a pure resolver result, response cache, transport adapters, and
an idempotent domain-knowledge projector. Preserve the existing relation from
IP addresses to domain-rule bitmaps; do not collapse it to one domain per IP.

Acceptance:

- Request routing still occurs before cache lookup and reject rules cannot be
  bypassed by a cache hit.
- Cache scope, TTL, stale-while-revalidate, eviction, and wire responses are
  byte-compatible with the legacy corpus where timestamps are fixed.
- Projection handles multi-domain IPs, TTL expiry, policy replacement, retry,
  and reference cleanup without cross-epoch writes.

### 6. Flow and Egress Bindings

Add an explicit flow registry on top of the existing sharded endpoint pools:
`FlowKey -> RouteBinding -> EgressBinding -> transport endpoint`. A flow key is
derived from existing tuple, route-scope, and NAT semantics. Do not use one
goroutine per flow.

Acceptance:

- Ordinary packets only look up the binding; they do not rerun routing or
  choose a dialer.
- UDP full-cone/symmetric reuse, QUIC upgrades, endpoint creation races,
  retries, and NAT expiry match legacy traces.
- Dialer health does not destroy a successfully forwarding endpoint.

### 7. Runtime Supervisor and Reload

Move process-lifetime BPF objects, listeners, shared DNS stores, workers, and
pools under a runtime supervisor. A generation owns immutable policy state;
flows hold leases. Reload is prepare, warm, validate, publish, drain, and
reclaim.

Acceptance:

- New flows use only the published epoch; live flows follow the documented
  compatibility policy.
- Failure at any preparation or cutover point rolls back without a packet-loss
  window.
- Concurrent reload, shutdown, DNS warmup failure, BPF failure, and health
  flapping tests have no resource leaks or stale-generation BPF writes.

### 8. Controlled Cutover and Legacy Removal

Enable each completed path behind an internal feature gate, beginning with
shadow-only evaluation. Keep compatible readers and rollback support for at
least one release cycle before deleting legacy state transitions.

Acceptance:

- Full compatibility corpus, fuzzing, race tests, eBPF tests, and long-running
  TCP/UDP/QUIC/reload soak tests pass.
- Performance is not worse than the Phase 0 gate and improvements are visible
  in the recorded metrics.
- Legacy code is removed only after no supported rollback path depends on it.

## Required Verification

Every authoritative phase requires `go test ./...`, focused race tests for
affected control packages, `make ebpf-sync-check`, `make ebpf-lint`, and
`make ebpf-test` where the environment supports kernel tests. Failures block
promotion; they are not waived by an expected performance improvement.
