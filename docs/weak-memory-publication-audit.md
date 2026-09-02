# Weak-memory publication audit

Baseline: `dd57d5cabf879dda466ee8f1c1ddc614712d687d` (`kdae`)

Scope: Go-side generation publication, reload ownership, DNS runtime/cache
publication, process-flow ownership, maintenance workers, TC HookSet handoff,
and userspace-to-BPF routing publication.

## Memory-model rules used

- Go `sync/atomic` operations are sequentially consistent. If an atomic load
  observes an atomic store, writes sequenced before the store are visible to
  reads sequenced after the load.
- Constructing an immutable object, then publishing its pointer with one atomic
  store, is safe on amd64, arm64, and riscv64. The reader must reach the object
  through the corresponding atomic load, and the published object must not be
  mutated without its own synchronization.
- Sequential consistency does not combine several atomic variables into one
  transaction. A reader can observe a tuple assembled from different logical
  generations even when every individual access is race-free.
- Mutex unlock/lock, channel send/receive or close/receive, and goroutine start
  provide their normal Go happens-before edges. A successful race-detector run
  does not prove a multi-atomic publication protocol.
- Go's memory model does not make several BPF map update syscalls atomic. The
  routing protocol must isolate writes in an inactive slot and use one selector
  update as its kernel-visible commit point.

## Risk-ranked inventory

| Risk | Publication | Publisher | Reader | Synchronization and legal state | Audit result |
| --- | --- | --- | --- | --- | --- |
| Confirmed | DNS runtime behavior | `DnsController.updateRuntime` | `currentOptimisticCacheConfig`, `currentQtypePrefer`, cache janitor and request paths | Baseline used four independent behavior atomics followed by `runtimeState.Store`. Each scalar was race-free, but no atomic represented the behavior tuple. | A single read could return `enabled`, TTL, and max-size values from different reload generations. Fixed by putting all behavior fields in immutable `dnsControllerRuntimeState` and publishing one pointer. |
| Confirmed | Packed DNS response | `prepackResponseBeforeStore`, `prepackResponseWithTTL` | `GetPackedResponseWithApproximateTTL`, `GetStaleResponse`, `CloneForReload` | Baseline stored wire pointer, TTL, and creation time independently. COW protected the bytes from mutation but did not publish the metadata transactionally. | A reader could observe new wire bytes with old TTL metadata. Fixed with immutable `dnsPackedResponse { wire, ttl, createdAt }` and one pointer store. |
| High, safe | Active `ControlPlane` plus execution-owner registry | `publishActiveControlPlane`, `runtimeSupervisor.publishPrepared` | active DNS dispatch and `publishedRoutingEpochExecutionOwner` | Candidate construction, datapath commit, peer/provisional registration, and DNS handoff finish before supervisor publication. Registry and pointer changes occur under `activeControlPlanePublication.mu`; readers hold its read side while selecting and admitting work. | A load of the new plane reaches fully initialized immutable generation fields. Owners cannot be mixed with a pointer from another registry transaction because both are inspected under the same mutex. |
| High, safe | Runtime generation ownership | `runtimeSupervisor.installPrepared`, `publishPrepared`, `rollbackPrepared`, `shutdown` | reload, retirement, and shutdown orchestration | `active`, `prepared`, `retiring`, and `closed` are plain fields protected by one mutex. `shutdown` returns one ownership snapshot while holding that mutex. | Every reader observes a legal supervisor state; there is no independent atomic publication. Cleanup ownership transfers exactly once through the snapshot and `cleanupOnce`. |
| High, safe | Immutable control-plane generation state | `NewControlPlaneWithContextOptions` | routing, TCP/UDP dispatch, DNS option construction | `outbounds`, policy identity, matcher, resolver slice, and referenced-outbound map are built before the `ControlPlane` is installed or atomically published. They are not rewritten after publication. | The active-plane pointer's publication edge covers these fields. Internal matcher/trie data is immutable after construction. |
| High, safe | Session manager plus ownership bit | `AttachSessionManager`, `sessionManagerForFlow` | TCP/UDP flow adoption, janitor, active DNS fallback | Plain compatibility fields are changed under `sessionManagerMu`, then one immutable `controlPlaneSessionManagerBinding { manager, owned }` is stored. Readers prefer one pointer load. | New manager with old ownership is impossible through the binding. Manager internals have their own locks/atomics. |
| High, safe | SessionManager flow-map handle | `prepareControlPlane`, `AdoptProcessFlowDatapath` | UDP release/pin and janitor paths | `udpBPF` is changed under `udpStateMu`; operations that require map-lifetime exclusion hold the read or write side. The successor pointer is stored only after previous-owner validation. | Map cleanup cannot combine an adopted pointer with stale protected pin state. Fresh reload rollback restores the validated previous owner. |
| High, safe | Routing policy in BPF maps | `PrepareRoutingEpoch`, routing builder, DNS cache replay, `StageRoutingEpoch`, `PublishRoutingEpoch` | `route()` in `control/kern/tproxy.c` | Rules, metadata, unique LPM references, domain projection, and epoch metadata are populated in the inactive slot. Only then does one `active_routing_epoch_map[0]` update expose the slot. `route()` samples the selector once and uses that slot for every keyed lookup. | New selector plus incomplete new-slot content is excluded by update order and inactive-slot isolation. This is a kernel protocol, not a Go atomic-publication claim. |
| Medium, safe | Routing peer pointer and slot | `LinkRoutingEpochPeer` | owner resolution and `routingEpochExecutionMatches` | Pair linkage is protected by `routingEpochPeerLinkMu` plus both peer mutexes. Slot is stored before `routingEpochSlotKnown=true`; Go's SC order means a reader that sees `known` also sees the preceding slot. A control plane's slot is immutable across its lifetime. | New peer with old slot is excluded. Shared reload deliberately keeps one datapath generation while policy slots differ. |
| Medium, safe | BPF object pointer and datapath generation | core construction, `InjectBpf`, `LinkRoutingEpochPeer` | BPF accessors and attributed owner matching | Fresh objects are registered with a nonzero generation before publication. Shared peers validate object identity and copy the same registered datapath generation before they are exposed. Restore paths re-inject the same registered object. | The generation identifies the BPF object/program set, not each policy epoch. Keeping it constant across a shared-object slot flip is legal. |
| High, safe | Maintenance target and rollback predecessor | `bpfMaintenanceBinding.activate`, `rollback`, cleanup adoption | ringbuf reader, janitor request routing, rollback | The target plane is fully initialized before `active` CAS. Activation stores `previous` before `activated=true`; a rollback that successfully changes `activated` from true to false therefore observes the predecessor under SC. Cleanup-runtime adoption validates shared flow-state maps and uses CAS. | A new target never depends on unpublished predecessor metadata. Failed/stale CAS operations stop rather than overwriting a later owner. |
| Medium, safe | Ringbuf event target | maintenance activation/deactivation | `readEvents` | One goroutine owns the ringbuf reader. Each event loads one active target pointer and only reads generation fields that remain valid for the event call. Runtime shutdown closes the reader and joins workers before releasing the last runtime. | No data race or partially initialized target. An event already read during a target swap may cause a benign health probe against the later target; it does not mutate routing generation state. |
| High, safe | TC HookSet ownership and program references | prepare/adopt/restore/finalize handoff | TCX/classic adapter updates and close paths | `tcHookOwnershipMu` and per-core `tcHookMu` serialize ownership. Prepare records rollback state, TCX/classic replacement completes, adopt transfers the pointer under the ownership mutex, restore precedes rollback, and finalize discards snapshots only after supervisor publication. | No new HookSet owner can carry old program/map references. No HookSet redesign was required. |
| High, safe | DNS listener/controller handoff | controller reuse, `reuseDNSListenerFrom`, rollback restore | listener `Controller`, `ActiveDnsController`, active DNS dispatch | Listener stores one fully initialized `ControlPlane` pointer. Handoff ownership is only interpreted under `dnsHandoffMu`; readers that only need the controller load the pointer. Transfer/restore runs under the active-publication lock before old resources are closed. Controller handle admission is counted before that lock is released. | New listener owner plus old controller runtime is excluded at handoff completion; admitted old requests hold the controller lifetime gate. |
| High, safe after fix | DNS shared runtime | `updateRuntime`, `ReuseForReload` | request handlers, cache projection and long-lived workers | `dnsControllerRuntimeState` is fully constructed, including behavior fields, before one `runtimeState.Store`. Cache publication takes `runtimeMu.RLock` and rechecks pointer identity before committing membership and BPF projection. | A reader of one runtime snapshot sees exactly one routing callback/epoch/behavior generation. Published snapshots are not mutated. |
| Medium, safe | DNS cache membership and BPF projection | cache update/restore and async projection worker | DNS cache readers and domain-route map writer | Cache wrappers are initialized before `sync.Map.Store`. Projection holds `runtimeMu` and `cacheProjectionMu` and checks task/cache/runtime epoch identity. Retry tasks carry the epoch and cache pointer. | A stale task cannot publish an old bitmap as the current runtime epoch. Per-entry BPF map writes are idempotent and slot-scoped. |
| Medium, safe | Dialer selection snapshot | `DialerGroup` selection-state rebuild/swap | dial selection and health reporting | Policy, annotation references, and alive-set references are assembled before one atomic pointer store. Published pointer fields are stable; mutable alive sets synchronize internally. Old callbacks are unregistered after the swap. | Readers cannot combine a new policy with an old alive-set array through publication. |
| Low, safe | Upstream resolver result and retry time | `UpstreamResolver.Init` | concurrent resolver initialization | Retry timestamp is written before the error sentinel. A reader that sees the sentinel sees the preceding timestamp under SC. Success state does not interpret the retry timestamp. | No result/timestamp mixed state affects success; error retry throttling is coherent. |
| Low, safe | Package caches and runtime stats | QUIC failure cache setter, daedns router setter, runtime-stats publisher | packet sniffing, resolver lookup, traffic recorders | Each pointer publishes a fully built object. Mutable internals use shard locks or atomics. Retirement swaps nil or uses compare-and-swap; objects are not freed while a loaded pointer is in use. | Standard immutable-pointer publication proof applies. |
| Medium, safe | UDP endpoint generation and tuple snapshot | endpoint creation, tuple tracking, dialer invalidation | pool hit classification, cleanup and packet dispatch | Endpoint immutable fields and sampled dialer epoch are initialized before insertion under the shard lock. The tuple pair is one immutable atomic snapshot. Epoch counters are monotonic; a mismatch makes an endpoint stale. Reverse indexes and lifecycle state have dedicated locks/atomics. | Readers may observe an endpoint become stale after lookup, which the write/retire contract already permits; they do not observe a fabricated generation tuple. |
| Low, safe | Monotonic gates/counters | connection rejection, execution close, DNS handle close, reload flags | admission and shutdown paths | These atomics do not encode one multi-field generation. Gate protocols use precheck, lease/counter acquisition, and recheck. Any observed closed/rejected bit causes rejection; all intermediate bit combinations are legal. | They are synchronization gates, not side-field publications. |
| Low, safe | DNS BPF sync timestamp/hash | `NeedsBpfUpdate`, `MarkBpfUpdated` | projection scheduling/reconciliation | The timestamp is a best-effort CAS claim and the hash is an idempotence hint. They do not identify a generation or authorize cleanup. A mixed observation can only delay within the configured minimum interval or repeat an idempotent projection. | Keeping them independent is intentional; merging them would add allocation without eliminating an illegal state. |
| Confirmed | Userspace active-slot cache | BPF selector lookup and publish/rollback invalidation | `ownsActiveRoutingEpoch` on UDP routing-result reuse | Baseline stored slot, timestamp, and valid bit independently and invalidated only after the selector syscall. A lookup that sampled the old selector could resume after cutover and republish that old slot with a fresh timestamp. | The old plane could temporarily pass the active-owner test and reuse an old routing result after the kernel commit. Fixed with one immutable cache snapshot, an in-progress token installed before the selector update, and token CAS so neither pre-invalidation nor in-progress lookups can overwrite the publisher. |

## Confirmed failures and fixes

### DNS behavior tuple

Publisher at baseline:

1. store optimistic-cache enabled;
2. store optimistic-cache TTL;
3. store max cache size;
4. store the new runtime pointer.

Reader: `currentOptimisticCacheConfig` loaded the three atomics separately.
Legal states were `(false, 101, 1001)` and `(true, 202, 2002)`. The litmus
repeatedly observed illegal states including `(true, 101, 1001)` and
`(true, 202, 1001)`. This is not a Go data race. It is a logically impossible
multi-atomic tuple and is allowed by sequential consistency through ordinary
interleaving.

The fix moves the tuple and `qtypePrefer` into `dnsControllerRuntimeState`.
The publisher initializes the complete immutable struct, takes `runtimeMu`, and
stores one pointer. A reader loads that pointer once. The field initialization
is sequenced before the store; a load that observes the pointer synchronizes
before all following field reads, so the proof is architecture-independent.

### Packed DNS response

Publisher at baseline stored a new wire pointer before storing its TTL and
creation timestamp. The litmus parsed the atomically loaded DNS wire and
compared its answer TTL with the independently loaded metadata. It repeatedly
observed wire TTL 202 with metadata 101 and the inverse.

The fix publishes `dnsPackedResponse` with one atomic pointer. Its wire slice,
TTL, and creation timestamp are immutable. Refresh remains COW. A separate
atomic boolean only admits slow-path refresh work; it is not used to interpret
the published response and therefore is not a side field. Cache-hit packet work
still performs one pointer load and takes no lock.

### Active routing-slot cache

The baseline cache published slot, observation time, and validity with three
atomics. `PublishRoutingEpoch` and `RollbackRoutingEpoch` invalidated that cache
only after the kernel selector update. A slow miss reader could therefore load
the old selector, cross the invalidation and cutover, and then store the old
slot with a new timestamp and `valid=true`. The old control plane could pass
`ownsActiveRoutingEpoch` and reuse an old UDP routing result after the kernel
commit point.

The fix uses one immutable `routingEpochActiveSlotSnapshot`. A selector writer
first stores a unique `publishing` token in both linked peers, updates the kernel
selector, and then stores a complete new cache snapshot in both peers. If the
selector update fails, the publication transaction restores each peer's exact
pre-attempt snapshot instead of leaving the hot path in map-lookup mode. A
reader that sees `publishing` may return its synchronous map result for that
call but cannot cache it. Any other miss reader records the pointer it observed
before its map lookup and may cache the result only with a pointer CAS. If invalidation
or another publication changed the token, the CAS fails and the reader retries.
Because the old snapshot remains referenced by the reader, its address cannot
be recycled into an ABA match. The cache-hit path improves from three atomic
loads to one and remains lock-free.

## BPF transaction proof and residual risk

For a new routing epoch, synchronous map update syscalls finish the inactive
slot before `PublishRoutingEpoch` updates the active selector. The packet
program loads that selector once and keys all policy lookups by the sampled
slot. This excludes `new selector + unfinished new slot` without relying on CPU
store ordering.

The remaining unproved kernel question is reclamation, not initial publication:
an invocation that sampled the old selector immediately before a flip might in
principle overlap later cleanup of the inactive slot. The current implementation
waits for userspace generation retirement before cleanup, which is much longer
than normal TC program execution, but this audit did not establish a formal
kernel RCU grace-period edge for every supported kernel. No reproducer was
obtained. This should remain a residual risk unless kernel-version-specific
execution semantics or a real-kernel stress test falsifies it; it is not evidence
for adding a packet-path selector, dispatcher, lock, or tail call.

## Change contract

### ROUTING-EPOCH-1: linked publication is single-writer

Current status: an invariant supplied by reload orchestration, not enforced by
`controlPlaneCore`. Publish and rollback calls for a linked pair must not run
concurrently. Each core owns a `routingEpochMu`, but a publication transaction
also swaps the peer's userspace active-slot cache without taking the peer's
mutex.

Failure condition: if future orchestration permits both linked planes to call
publish or rollback concurrently, interleaved selector updates and peer-cache
commit/restore operations can leave the cache naming a slot other than the last
successful map update.

Required action before parallelizing: serialize the complete linked-pair
selector/cache transaction outside the packet path, add adversarial concurrent
publish/rollback/failure tests, and run real-map routing plus supported-kernel
lifecycle gates. Independent per-core locking is not sufficient.

### ROUTING-EPOCH-2: old-slot cleanup has no proven kernel grace edge

Current status: `finalizePreviousRoutingEpoch` runs only after userspace
retirement and drain. This is a long practical delay, but it is not a formal
proof that every TC invocation which sampled the old selector has completed
before old slot-scoped values are cleared.

Failure condition: an invocation samples the old slot before selector flip,
is delayed across retirement, and performs a later lookup while userspace
clears that slot. No supported-kernel reproducer or authoritative grace-period
proof was established by this audit.

Required action before moving cleanup earlier, shortening its drain dependency,
or making it concurrent with cutover: obtain kernel-version-specific evidence
for all supported kernels or a real-kernel test that exercises the delayed
old-selector lookup. Do not compensate with a packet-path Go lock, extra
selector, tail call, or dispatcher.

These contract IDs are repeated beside the implementation in
`control/routing_epoch.go` so code search and future scoped work encounter them.

## Regression evidence

`control/weak_memory_publication_test.go` contains three publication litmus
tests plus a failed-publication recovery test. On the baseline, both
high-concurrency DNS tests failed in every one of ten repeated runs, and the
active-slot stale-writer interleaving failed deterministically. After the
snapshot changes, all tests passed repeated native, race-enabled, ARM64, and
RISC-V runs. The runtime test rejects behavior tuples that belong to no
configured generation. The packed-response test parses the real DNS wire and
requires its TTL to match metadata from the same loaded snapshot. The routing
tests prove that a lookup which began before invalidation cannot replace the
post-cutover cache token and that a failed selector update restores both linked
peers' previous cache snapshots.
