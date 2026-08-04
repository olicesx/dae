---
sprint: 8
task: T1
phase: dev
status: complete
completed_tasks: 1
artifacts_changed_since_last_observe:
  - control/control_plane.go (981 lines removed)
  - control/control_plane_parse.go (new, 85 lines)
  - control/control_plane_dns.go (new, 307 lines)
  - control/control_plane_datapath.go (new, 396 lines)
  - control/control_plane_dialtarget.go (new, 259 lines)
dev_self_tests_passed: true
---

# Sprint 8 T1 — Trace Log

## Procedure

Used a hybrid approach: `replace_string_in_file` for the smallest cluster (parse, 68 lines)
to validate the toolchain, then a Python extraction script (`tmp/sprint8-split.py`) for the
3 larger clusters to avoid transcription errors on ~900 lines of code.

### Cluster 1: parse → control_plane_parse.go

- **Method**: `replace_string_in_file` (create new file + delete from source)
- **Functions moved** (4): `ParseFixedDomainTtl`, `ParseGroupOverrideOption`,
  `parseGroupOverrideOptionWithRuntime`, `inheritGroupOptionRuntime`
- **Lines**: original 1027–1094 (68 lines)
- **Imports**: `fmt`, `strconv`, `strings`, `dialer`, `config`, `logrus` (6, manually analyzed)
- **Build**: EXIT=0, VET=0 after extraction

### Cluster 2: dns → control_plane_dns.go

- **Method**: Python script (`tmp/sprint8-split.py`) — exact function boundary detection via
  `^func` + `^}` matching, auto-import analysis
- **Functions moved** (18): `CloneDnsCache`, `StreamDnsCacheForReload`, `SetReloadDnsCacheSource`,
  `SetReloadDnsCacheStreamSource`, `ClearReloadDnsCacheSource`, `cloneDnsReloadCacheForCutover`,
  `dnsReloadCacheStreamForCutover`, `projectDnsReloadCacheStream`, `refreshDnsReloadCacheForCutover`,
  `ActiveDnsController`, `dnsRequestContext`, `SharesActiveDnsControllerWith`,
  `DetachDnsController`, `replaceDNSHandoffController`, `clearDNSHandoffControllerIfMatch`,
  `takeDNSHandoffController`, `EnableDNSHandoff`, `SetDNSHandoffController`
- **Lines**: 277 function lines (original 1230–1528, two sub-clusters)
- **Imports**: `context`, `fmt`, `time` (3)

### Cluster 3: datapath → control_plane_datapath.go

- **Method**: Python script
- **Functions moved** (11): `closePublishedListenerFiles`, `publishListenerSockets`,
  `PublishListenerSockets`, `commitInterfaceBindings`, `replayDnsReloadCache`,
  `releaseCommittedDNSReloadState`, `CommitPreparedDatapath`, `CommitPreparedBpfHookFlip`,
  `RollbackPreparedBpfHookFlip`, `RebuildReloadDatapath`, `RestoreDatapathForReloadRollback`
- **Lines**: 368 function lines (original 1732–2110)
- **Imports**: 8 (initial 9, `net` removed as false positive)
- **Note**: auto-import analysis had 1 false positive (`net` matched a parameter name, not
  the package) — caught by `go build` and removed

### Cluster 4: dialtarget → control_plane_dialtarget.go

- **Method**: Python script
- **Functions moved** (9): `ActivateCheck`, `OnHealthCheckSuccess`, `ChooseDialTarget`,
  `lookupRealDomainCache`, `resolveBootstrapIp46`, `triggerRealDomainProbe`,
  `probeAndUpdateRealDomain`, `resolveIp46WithBootstrapResolvers`, `cleanupNegativeCaches`
- **Lines**: 227 function lines (original 2175–2392)
- **Imports**: 13 (initial 15, `outbound` and `routing` removed as false positives — matched
  parameter names, not packages)

### control_plane.go import trimming

After all extractions, 2 imports became unused in control_plane.go:
`github.com/daeuniverse/outbound/netproxy`, `github.com/daeuniverse/outbound/protocol/direct`.
Removed via `tmp/sprint8-fix-imports.py`.

## Issues encountered

1. **PowerShell `$?` expansion (L7)**: `echo EXIT=$?` in inline `wsl bash -c "..."` commands
   returns PowerShell's `$?` (True/False), not bash's exit code. Resolved by writing all
   verification commands to `tmp/sprint8-*.sh` script files.
2. **Auto-import false positives**: Simple qualifier-based import analysis (`\bname\.`) matches
   parameter/variable names that happen to share package names (e.g., `outbound` parameter in
   `ChooseDialTarget(outbound consts.OutboundIndex, ...)`). 3 false positives across 2 files,
   all caught by `go build` and removed. For future splits, consider AST-based analysis.
3. **Function name typo in task**: Task listed `SharesActiveDnsController` but actual function
   is `SharesActiveDnsControllerWith`. Used correct name from grep.

## Verification results (all passed)

```
VET_EXIT=0
BUILD_EXIT=0 (tags=trace, GOEXPERIMENT=heapminimum512kib,randomizedheapbase64)
TEST_EXIT=0 (control 9.821s, component cached)
EBPF_LINT_EXIT=0 (C sources untouched)
git diff --numstat: 0 981 control/control_plane.go (pure deletions, no modifications)
```

## Line counts

| File | Lines |
|------|-------|
| control_plane.go | 3334 (was 4315, −981) |
| control_plane_parse.go | 85 |
| control_plane_dns.go | 307 |
| control_plane_datapath.go | 396 |
| control_plane_dialtarget.go | 259 |
| **Total** | **4381** (original 4315 + 66 headers/imports) |

## Commits

None — staged but uncommitted per task instructions. Orchestrator to review and commit.
