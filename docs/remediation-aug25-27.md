# Remediation plan: dae + outbound (2026-08-25 .. 2026-08-27)

Status: implemented in the local checkouts (`/root/outbound`, `/root/dae`). dae `go.mod` replace points at `/root/outbound` until a published pseudo-version exists.
Artifact revisions this plan is bound to:

- dae: `kdae` `7cfeb91e398ad6e764ec0ea50252cf5370d400fe`
- outbound: `perf/complete-optimizations` `e030f04c3bb1d80e416e28323c8a9e9cb7abf16d`

Goal: keep the verified wins, fix the HEAD correctness bugs and the named performance anti-patterns, and lock the invariants with tests that would have caught this window.

Do **not** revert the window. The failures are localized. A blanket rollback throws away real UDP/DNS/relay wins.

---

## 0. Decision summary

| Bucket | Action |
|---|---|
| Verified wins | Keep. Do not rewrite. |
| P0 protocol / lifecycle bugs at HEAD | Fix in outbound first, pin into dae, then dae-side leftovers. |
| P1 semantic lies / residual correctness | Fix next; small, testable. |
| P2 hygiene / measurement | After P0/P1; no behavior change. |
| Uncommitted outbound dirty tree | CRLF / gofmt only. Either discard or commit as `chore: normalize line endings` — not a feature. |

Execution order is mandatory: **outbound P0 → outbound tests green → dae pin → dae P0/P1 → P2**.
dae consumes outbound via `go.mod` replace. Shipping dae fixes against a still-broken outbound pin is not a remediation.

---

## 1. Keep (do not revert, do not “simplify away”)

These are net wins. Remediation must preserve them.

### dae

| Commit / area | Why it stays | Guardrail while fixing |
|---|---|---|
| `f1a63c5d` UDP pool Get fusion | FullCone cache-hit 2 Gets → 1. Prefetch is guarded by `bindingHit`. | Keep `control/udp_pool_get_count_test.go` counts. |
| `6a335b8c` `epochCounts` retained-endpoint gate | Removes per-packet O(flows) scan. Tally rebuilt from snapshot; UDP epochs immutable. | Keep `session_manager_retained_gate_test.go`. |
| `779559bb` 4 Hz `onActive` coalescing | Shared `lastActiveNano` was a false-sharing hot word. 250 ms lag is safe vs 30 s / 5 min idle. | Do **not** put per-chunk atomics back. The leftover bug is `bufioConn` dropping `onActive`, not coalescing. |
| `a7c461b2` `needs`-gated `Prefix2bin128` / domain bitmap | Skips 128-byte key builds when no rule reads them. | Keep `control/routing_matcher_needs_test.go`. |
| `779559bb` MatchDomainBitmap RWMutex memo | Hit = RLock + map vs AC/trie walk. Once-poisoning is already gone. | Do not bring `sync.Once` back. Do not put a Mutex on the hit path. |
| `29dcabe6` DNS forward uses `baseContext()` | Shutdown/reload must cancel in-flight forwards. | Do not restore `context.WithoutCancel`. |
| `1a040eb1` identity-based preference-wait remove | Bare-qname delete races a newer waiter. | Keep identity compare in `remove` / `notifyPreferred`. |
| `1a040eb1` bounded real-domain set (vs bloom) | Unbounded bloom self-seals. Bound stays. | Replace random eviction with real FIFO (P1), do not restore bloom. |
| `1ce90de6` DNS ingress accounting + drop dead fast-path duplicate | Dead unpack removed; accounting is two atomics. | Leave accounting in the ingress task. |
| `6dabeaa8` health-check print gating | Startup noise, not a hot path. | Keep. |
| Dead-code deletions (`caa4074e`, `a6b2e5be`, helper drops) | Production-idle code. | Do not resurrect TTL machinery or the async evictor. |

### outbound

| Commit / area | Why it stays | Guardrail |
|---|---|---|
| `0702558` socks5 polling ReadFrom 3-byte offset | Real framing fix. | Existing socks5 packet tests. |
| `53b5c77` + grpc remainder `(0,nil)` | Cert-pool errors retryable; leftover hunk no longer spins. | Do not memoize errors in `Once`. |
| `7ef9323` mux oversize → error | Truncate-and-continue was a desync. | Keep reject-on-oversize. |
| `8e2b540` TUIC incremental uni-stream parse | Measured: ~270–320 ns / 12 alloc → ~154–177 ns / 9 alloc. | Do not restore `binary.Read` + `bytes.Reader`. |
| `89233df` TUIC conn-private write scratch | `SendDatagram` copies; scratch reuse is safe. | Keep `writeMu` order; nil scratch on Close. |
| `1764decc` conn-private frames + close-underlay-first | ss/vmess/juicity frames never `pool.Put`; Close vs blocked-Read deadlock gone. | Do not Put conn-private frames. Do not lock readMutex before underlay Close. |
| `7f9f4b5` retryable `resolveTarget` | Fullcone UDP lives for hours; a first-write DNS blip must not poison the conn. | Do not `Once`-memoize resolve errors. |
| `75dfca6` **write** side only (`writeLocked` + `borrowPacketWriteBuffer`) | That is the real alloc win. | Keep the write path. Rewrite only `ReadFrom` (P0). |
| `ecbafad` metadata IP carry | Also stops a `To4()[:4]` nil panic. | Keep. |

---

## 2. P0 — correctness bugs at HEAD (ship blockers)

### P0-1  Trojan UDP CRLF skipped (`outbound`)

**File:** `protocol/trojanc/packet.go`
**Cause:** `75dfca6` copied juicity `ReadFrom` onto trojan. Juicity `SealUDP` is `addr+LEN+payload`. Trojan `SealUDP` is `addr+LEN+CRLF+payload`.
**Trigger:** any trojan/trojanc UDP datagram.
**Impact:** first payload is `\r\n` + truncated data; every later datagram misframes.

**Keep:** `writeMutex` + `borrowPacketWriteBuffer` + overflow-discard shape.
**Change `ReadFrom` to:**

1. `Unpack` metadata (unchanged)
2. Read 2-byte length
3. Read 2-byte CRLF; fail if not `{13,10}`
4. If `length <= len(p)`: `ReadFull(p[:length])`
5. Else: `ReadFull(p)` then `CopyN(Discard, length-len(p))` so the stream stays framed

Do **not** share this function with juicity. Twin alignment is the anti-pattern.

**Tests** (new `protocol/trojanc/packet_roundtrip_test.go`):

- `WriteTo` then `ReadFrom` of `"HELLO"` yields `"HELLO"`, not `"\r\nHEL"`
- Two datagrams back-to-back stay framed
- Caller buffer smaller than payload: prefix returned, remainder discarded, next datagram intact
- Invalid CRLF → error, no silent skip

**Done when:** `go test ./protocol/trojanc/ ./protocol/juicity/` pass; juicity tests still assert `Len()+2+payload` wire (no CRLF).

---

### P0-2  Restore client/server header dispatch; never retry a half-consumed header (`outbound`)

**Files:**

- `protocol/juicity/stream_conn.go`
- `protocol/trojanc/conn.go`
- `protocol/vless/conn.go`

**Cause:** `875a4b5` replaced `sync.Once` (which swallowed header errors) with “always read the request/response header and retry”. It also deleted `IsClient` branching. `headerReady` is declared and never written.

**Correct policy (library, not dae-as-client):**

| Proto | Client first Read | Server first Read |
|---|---|---|
| juicity | no req header on read (client already wrote it) | `readReqHeader()` |
| trojanc | no req header on read | `ReadReqHeader()` |
| vless | `ReadRespHeader()` | `ReadReqHeader()` |

**Error policy:** `io.ReadFull` that fails after consuming bytes cannot be retried. Sticky terminal error, do not set `readHeaderDone`:

```go
if c.headerErr != nil {
    return 0, c.headerErr
}
if !c.readHeaderDone {
    if err := c.readRoleHeader(); err != nil {
        c.headerErr = err
        return 0, err
    }
    c.readHeaderDone = true
}
```

Delete unused `headerReady`.

**Do not:** retry header parse; treat “Once was wrong” as “unconditional ReadReqHeader is right”.

**Tests:**

- juicity client (`IsClient=true`): first `Read` must not call `readReqHeader`; payload bytes pass through
- juicity server: first `Read` parses network+addr, then payload
- trojanc: same split
- vless client: `ReadRespHeader` (version + addons); vless server: `ReadReqHeader`
- Header `io.ErrUnexpectedEOF` after partial consume: second `Read` returns the same error, does not parse leftover as a new header

**Done when:** those tests fail on current HEAD (red) and pass after the fix (green).

---

### P0-3  HTTP/2 pool: MarkDead / ident / mappings must use the scoped key (`outbound`)

**File:** `protocol/http/conn.go`
**Cause:** `e030f04` keyed the live list with `namespace|magic|addr` but `poolIdent.addr`, `addr2Dialer`, `addr2Somark`, `MarkDead`, `cleanupConnListLocked` still use bare `addr`.
**Trigger:** reload / chain swap, then the dead conn is marked, or a second namespace shares the host:port.
**Impact:** dead conns leak in the scoped list; cleanup deletes the wrong map key; `GetClientConn` can dial with a stale chain.

**Change:**

- `poolIdent` stores `key string` (the full `scopeKey+"|"+addr`), not bare `addr`
- `acquireConnList` / `releaseConnList` / `cleanupConnListLocked` / `MarkDead` all use `ident.key`
- `registerAddrToDialerMapping` / `addr2Somark`: either key by `fullKey`, or keep a parallel addr map **only** for `GetClientConn` (http2’s interface only supplies `addr`)
- Recommended split:
  - list + ident + cleanup: `fullKey` only
  - `GetClientConn(addr)`: create a **new** conn via the latest dialer registered for that addr (reload *should* use the new chain). It must call `GetConn` so the new conn lands in the new scope list, never in the old one
- `MarkDead` must not look up `h2ConnsPool[bareAddr]`

**Tests** (current `protocol/http/conn_test.go` still inserts by bare `addr` — that is why this shipped):

- Two namespaces, same `addr`: `GetConn` returns distinct lists
- `MarkDead` on ns1 conn removes it from ns1, leaves ns2 intact
- Empty ns1 list is deleted by `fullKey`, `addr2*` for ns2 remains
- After `MarkDead`, `GetConn` in ns1 does not return the dead `ClientConn`

Update the three existing MarkDead tests to go through `GetConn` or to insert with the real key.

**Done when:** `go test ./protocol/http/` covers two-namespace MarkDead.

---

### P0-4  `bufioConn.CopyRelayRemainder` must forward `onActive` (`dae`)

**File:** `control/tcp.go` (`bufioConn.CopyRelayRemainder`)
**Cause:** `9677bb3a` added the parameter and wired only the `reader==nil` branch. Port-53 non-DNS TCP wraps `bufioConn` (`tcp.go` ~197–207). After prefix drain, splice/copy runs with `onActive=nil`.
**Trigger:** TCP to port 53 that is not DNS, one-way traffic after the peeked bytes are gone.
**Impact:** `lastActiveNano` never refreshes on that direction; 5 min idle watchdog can kill a live flow.

**Change:** pass `onActive` into every branch:

- `relaySpliceCopyExact(..., record, onActive)` (already accepts it)
- both `relayCopyDirect(..., record, onActive)`
- do **not** use `io.Copy` without the refresher when a watchdog exists

`prefixedConn` is already correct; leave it.

**Tests** (new `control/tcp_bufio_relay_onactive_test.go`):

- Fake src/dst implementing `netproxy.Conn`
- `bufioConn` with empty reader buffer + `record != nil` splice/fallback path
- Assert `onActive` is invoked when bytes move
- Same for `Buffered() > 0` drain path

**Done when:** test fails on current HEAD, passes after the one-function change.

---

## 3. P1 — residual correctness and named anti-patterns

### P1-1  Real-domain set: implement FIFO or stop claiming it (`dae`)

**Files:** `control/real_domain_runtime.go`, `control/control_plane_dialtarget.go`, `control/real_domain_runtime_test.go`

Current eviction is `for k := range map { delete; break }` — random, not FIFO. The test never checks order.

**Preferred fix** (same shape as `matchCacheOrd`):

- `realDomainOrd []string`
- on insert of a new domain at cap: `evict := ord[0]; ord = ord[1:]; delete(set, evict)`
- on hit of an existing domain: do not re-append (confirmation stays; re-probe cost stays one-shot)

**Tests:** insert `cap+1` distinct names; assert the first inserted is gone and the last is present. Rename/remove any test that says FIFO but only checks `len <= cap`.

Do not restore the bloom filter.

---

### P1-2  Direct two-tier receiver: stop pretending 2 KiB is lossless (`outbound`)

**File:** `protocol/direct/packet_receiver_linux.go`

`MSG_TRUNC` + 2048-byte buffer **consumes** an oversized datagram; the first `>2 KiB` packet per conn is gone. `needBigBuffers` never resets, so one large packet re-pins 64 KiB for the life of the association (256 × 64 KiB ≈ 16 MiB — the original motivation).

**Do not** revert to always-64 KiB as the first move (that is a real memory win for DNS/WG-sized replies).

**Fix:**

1. Raise the small tier to **8192** (covers EDNS/DNSSEC and almost all QUIC; leaves jumbo/GSO as the upgrade case).
2. Keep MSG_TRUNC detection + upgrade for the rest of the burst.
3. Document in a code comment: the datagram that triggers the upgrade is not recoverable without `MSG_PEEK` (extra syscall on every packet — not worth it on this path).
4. Optional later: config/build tag `directPacketReceiverForceFull` for zero-drop deployments.

**Tests:**

- 1200-byte packet delivered on a fresh entry (small tier)
- 3000-byte packet: after the raise, must be delivered (this fails at 2048 today)
- 20 KiB packet: first may be dropped; second 20 KiB on the same entry must be delivered; `needBigBuffers == true`

---

### P1-3  MatchDomainBitmap memo: freeze the contract (`dae`)

**File:** `component/routing/domain_matcher/ahocorasick_slimtrie.go`

Hit path returns the **shared** `[]uint32`. Current callers are read-only, so HEAD is fine. In-place OR would poison every `DnsCache`.

**Change:** comment on `MatchDomainBitmap`: returned bitmap is immutable and aliased. Do **not** clone on the hit path (that undoes the memo). Add a test that a caller mutating the slice is considered a contract break (or that `DnsCache` / tracker always copy — tracker already copies).

Leave RWMutex + cap-512 FIFO + `Build()` clearing the memo.

---

### P1-4  Sticky header error must Close the underlay on fatal parse (`outbound`)

Follow-up to P0-2: `FailAuthErr` / version mismatch should Close, not leave a half-read TCP/QUIC stream for the relay to keep copying. Minimum: return the sticky error so the relay `forceClose`s; do not add a new goroutine.

---

## 4. P2 — hygiene, measurement, comments

Do after P0/P1. No user-visible protocol change.

| Item | Action |
|---|---|
| outbound dirty tree | `gofmt` + LF. One chore commit or discard. |
| `headerReady` leftovers | Deleted as part of P0-2. |
| `control/netkit_linux.go` peer-scrub comment | Make the comment match the argv actually emitted; if `ip link` rejects `peer scrub`, keep the existing fallback and say so. |
| TUIC benches | Point a bench at `readPacketFromStream`, not only native `processDatagram` / `bytes.Buffer` `Packet.WriteTo`. Record ns/op in the commit body. |
| `udpEndpointPoolGetObserver` | Leave (≤1 ns). Do not add a build tag unless it shows up in a profile. |
| `anytls` 4 KiB pooled bufio around TLS | Safe (sole-reader Put). Optional later: skip wrap when inner is TLS, consistent with `netproxy.NewBufferedReaderConn`. Not a P0. |
| TUIC non-Packet uni-stream → `forceClose` | Spec-correct. Add a one-line comment that non-conformant servers die with the tunnel. Do not silently ignore again. |

---

## 5. Performance anti-patterns — explicit “never again”

These caused the regressions. Fixes above are instances; this is the rule set for the next patch.

1. **Do not treat sibling protocols as the same codec.** juicity UDP ≠ trojan UDP. Share helpers only after the wire layout is copied into the test vector of **both**.
2. **Do not “fix” `sync.Once` by deleting role dispatch.** Once-poisoning → sticky error or `if err != nil { return }` **before** flipping the done bit. Client/server branches stay.
3. **Do not change a map key in Get and leave it in Delete/MarkDead/ident.** Any pool key change is a single commit that updates insert, lookup, and teardown together, with a two-namespace test.
4. **Do not put `sync.Mutex` / `sync.Once` on a per-flow DNS/routing hit path.** Hit path is `RLock` or lock-free. Compute off the lock. Never Once-memoize a value that `Build()` or eviction can invalidate.
5. **Do not claim FIFO/identity/onActive in the commit message without a test that would fail if the implementation is a map-range or a `nil` callback.**
6. **Do not drop datagrams as a memory optimization without a test named `...DoesNotDrop...` or an explicit `...DropsFirstOversize...` plus a documented limit.** Silent `continue` after `MSG_TRUNC` is a behavior change.
7. **Do not retry framing after `io.ReadFull` failure.** Bytes are gone. Close.

---

## 6. Sprint sequence (work units)

Each unit is one outbound or dae commit, bisectable, with tests in the same commit.

| # | Repo | Unit | Depends on |
|---|---|---|---|
| 1 | outbound | P0-1 trojan UDP ReadFrom + roundtrip tests | — |
| 2 | outbound | P0-2 header dispatch + sticky `headerErr` + role tests | — (parallel with 1) |
| 3 | outbound | P0-3 h2 scoped ident/MarkDead + two-namespace tests | — (parallel with 1–2) |
| 4 | outbound | P1-2 small-tier 8 KiB + oversize tests | — |
| 5 | outbound | tag / push; dae `go.mod` pin | 1–4 green |
| 6 | dae | P0-4 `bufioConn` onActive + test | 5 optional (no outbound API) |
| 7 | dae | P1-1 real FIFO + order test | — (parallel with 6) |
| 8 | dae | P1-3 bitmap immutability comment + alias test | — |
| 9 | both | P2 comments / benches / dirty LF | 1–8 |

Suggested owners: 1–4 one outbound patch series; 6–8 one dae patch series. Do not squash P0-1 with P0-2 (different protocols, different tests).

---

## 7. Verification gate (definition of done)

### outbound (after units 1–4)

```bash
go test ./protocol/trojanc/ ./protocol/juicity/ ./protocol/vless/ ./protocol/http/ ./protocol/direct/ ./protocol/socks5/ ./transport/grpc/ ./transport/mux/
go test -race ./protocol/trojanc/ ./protocol/juicity/ ./protocol/vless/ ./protocol/http/
```

Must include the new tests in §2–§3. Current HEAD is expected **red** on P0-1 and P0-2 tests (that is the point).

### dae (after units 6–8)

```bash
go test ./control/ ./component/routing/domain_matcher/ ./component/dns/ ./component/daedns/
go test -race ./control/ -count=1
```

Must include `tcp_bufio_relay_onactive_test.go` and a FIFO **order** test.

### Explicit non-goals for this remediation

- No new protocols, no eBPF map layout changes, no health-check policy changes.
- No rewrite of TUIC parse, ss/vmess buffer reuse, UDP Get fusion, or epochCounts.
- No attempt to make MatchDomainBitmap return a cloned slice on the hit path.
- No `MSG_PEEK` on every direct UDP packet.

---

## 8. Residual risk after this plan

- First jumbo/GSO datagram on a still-small direct receiver may still be dropped (P1-2 documents it; 8 KiB makes it rare).
- `GetClientConn(addr)` remains addr-scoped at the http2 interface boundary; isolation is guaranteed for `GetConn` + `MarkDead`. Two live chains to the same host used **only** via Transport.RoundTrip/`GetClientConn` still share the “latest dialer” mapping by addr. If that shows up in production, the follow-up is to stop using `GetClientConn` for redial and keep `ClientConn` lifetime inside `GetConn`.
- `Build()` vs `MatchDomainBitmap` still assume a matcher is not mutated in place after publish. Confirm no in-place rebuild on reload (today’s builder publishes a new instance). Out of scope unless a reload path is found that reuses the pointer.

---

## 9. What “complete” looks like in git

outbound: 4 commits (P0-1, P0-2, P0-3, P1-2) + optional chore LF.
dae: pin commit + P0-4 + P1-1 + P1-3.

Commit subjects (proposed):

```
fix(trojanc): consume CRLF in UDP ReadFrom
fix(protocol): restore role-based header read and sticky header errors
fix(http): key h2 MarkDead and ident by dialer scope
perf(direct): raise small UDP tier to 8KiB and test oversize upgrade
chore(deps): bump outbound fork to <sha>
fix(control): pass onActive through bufioConn relay remainder
fix(control): FIFO-evict the real-domain set in insertion order
docs(routing): freeze MatchDomainBitmap aliasing contract
```
