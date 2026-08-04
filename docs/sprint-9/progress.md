---
sprint: 9
task: T1
phase: dev
status: complete
completed_tasks: 1
artifacts_changed_since_last_observe:
  - control/control_plane_core.go (784 lines removed, 1409 → 625)
  - control/control_plane_core_bind.go (new, 644 lines)
  - control/control_plane_core_routing.go (new, 170 lines)
dev_self_tests_passed: true
---

# Sprint 9 T1 — Trace Log

## Summary

Pure mechanical split of `control/control_plane_core.go` (1409 lines) into 2 new files
in the same package `control`. No logic, signature, rename, or API changes. Bodies moved
verbatim. Same pattern as Sprint 8's `control_plane.go` split.

## Procedure

1. **Read** `control/control_plane_core.go` end-to-end; mapped all 44 top-level func
   declarations via `grep -nE '^func '` and confirmed exact line boundaries with `awk NR`
   (authoritative, avoiding the sed `cat -n` relative-number ambiguity).
2. **Import analysis**: grepped each cluster's line range for usage of every imported
   package to determine the exact import set per file (deterministic, not guessed).
   Caught two non-obvious "stays" in core: `io` (used by `cgroupAttachment` interface's
   `io.Closer`) and `ciliumLink` (used by `attachCgroupFunc` var).
3. **Python extraction** (`tmp/sprint9-split.py`): read with `newline=''` (preserves LF,
   avoids L19 CRLF risk), extracted by confirmed 1-indexed line ranges with content-level
   assertions (`check()` on start/end line prefixes), wrote new files + rewrote core.
4. **Off-by-one fix**: first run placed an extra `)` — original import block closes at L29
   (not L28 as initially assumed), so `body1` started at L30 not L29. Caught immediately by
   `go build`, restored from git, fixed, re-ran.

## Files

### control_plane_core_bind.go (644 lines, 14 functions)

Interface binding + qdisc utilities. Imports: `errors`, `fmt`, `os`, `path`, `regexp`,
`ebpf`, `ciliumLink`, `consts`, `ethtool`, `netlink`, `unix`.

Functions: `getIfParamsFromLink`, `linkHdrLen`, `buildClsactQdisc`, `addQdisc`, `delQdisc`,
`bindLan`, `_bindLan`, `setupSkPidMonitor`, `setupTCPRelayOffload`, `bindWan`,
`registerInterfacePattern`, `attachMatchingInterfaces`, `_bindWan`, `bindDaens`.

### control_plane_core_routing.go (170 lines, 7 functions)

Domain routing + udp conn state + tc filter helper. Imports: `errors`, `fmt`, `net/netip`,
`os`, `netlink`, `unix`.

Functions: `deleteTCFiltersByHandle`, `extractIPsFromDnsCache`, `BatchUpdateDomainRouting`,
`BatchRemoveDomainRouting`, `RetainUdpConnStateTuples`, `TransferRetainedUdpConnStateTuplesFrom`,
`ReleaseUdpConnStateTuples`.

### control_plane_core.go (625 lines, remains)

Kept all `var`/`type`/`const` declarations, `controlPlaneCore` struct, `newControlPlaneCore`,
BPF hook lifecycle (commit/rollback/activate/Flip/addBpfHookDetach/.../Close), and BPF
resource management (EjectBpf/EjectLpmIndices/.../startIfindexWatcher). Trimmed imports:
removed `net/netip`, `os`, `path`, `regexp`, `consts`, `ethtool`, `unix` (now unused in core).

## Gate results (`tmp/sprint9-gate.sh`)

| Check | Result |
|-------|--------|
| gofmt -l | clean (no output) |
| go vet ./control/... | VET_OK |
| go build -tags=trace ./... | BUILD_OK |
| go test -short ./control/... ./component/... | ok (all pass) |
| go test -race -short ./control/... | ok 10.876s |
| Function set match (old 44 == new 44) | FUNC_SET_MATCH |
| numstat core | `0 add / 784 del` |
| CRLF check | 0 matches (LF preserved) |

## Verbatim verification (three-channel)

Spot-checked critical seams against `git show 8e9d1276`:
- Core Close→EjectBpf seam: Close ends L462 `}`, blank L463, `// EjectBpf` L464. Clean.
- Bind bindDaens tail: `c.addManagedBpfHookCleanup(dae0DetachFunc)` / `return` / `}`. Matches original.
- Routing head: `// deleteTCFiltersByHandle` comment block intact; tail ReleaseUdpConnStateTuples `}`.

## Notes

- Changes left **uncommitted** per task instruction (orchestrator commits).
- `deleteTCFiltersByHandle` placed in routing file per task decision (used by BatchUpdate path).
