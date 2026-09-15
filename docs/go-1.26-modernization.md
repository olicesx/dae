# Go 1.26 modernization

Reference for the Go 1.26 toolchain pass applied to this tree. It records what the
toolchain changed, what was deliberately left alone, and which newer language and
runtime capabilities are available but not yet used.

Toolchain at the time of writing: `go1.26.8`, module directive `go 1.26.0`.

## What the toolchain changed

Go 1.26 turns `go fix` into the modernizer driver (`go tool fix help` lists the
analyzers). Run it through `go fix`, not `gofmt`-style manual edits, so the
rewrites stay reproducible:

```bash
# Always verify a reported file is actually part of the tagged build before applying:
go fix ./...                                   # real datapath build
go fix -tags dae_bpf_tests ./control/kern/tests/...
```

`go fix` only loads files whose build constraints are satisfied, so a single
`go fix ./...` misses files behind other tag sets. Run it once per tag set that
compiles different files (`dae_stub_ebpf`, `trace`, `dae_bpf_tests`, and the
default real build). For files the current tag set excludes it may also report a
stale diff; treat those as noise and confirm against the file on disk.

| Change | Shape | Files touched |
|---|---|---|
| `rangeint` | `for i := 0; i < n; i++` → `for i := range n`, `for range n` | 27 |
| `minmax` | if/else clamps → builtin `min`/`max` | 10 |
| `stringscut`, `stringscutprefix` | `strings.Index`/`HasPrefix`+`TrimPrefix` → `strings.Cut`/`CutPrefix` | 5 |
| `any` | `interface{}` → `any` (identical type; no API change) | 4 |
| `waitgroup` | `wg.Add(1)` + `go func(){ defer wg.Done(); ... }()` → `wg.Go(...)` | 4 |
| `reflecttypefor` | `reflect.TypeOf(T{})` → `reflect.TypeFor[T]()` | 3 |
| reflect iterators | `for i := 0; i < t.NumField(); i++` → `for f := range t.Fields()` | 3 |
| `mapsloop` | copy loop → `maps.Copy` | 3 |
| `stringsseq` | `range strings.Split(...)` → `range strings.SplitSeq(...)` (no slice allocation) | 2 |
| `slicescontains` | membership loop → `slices.Contains` | 2 |
| `testingcontext` | `context.WithCancel(context.Background())` + `defer cancel()` → `t.Context()` | 1 |
| `fmtappendf` | `[]byte(fmt.Sprintf(...))` → `fmt.Appendf(nil, ...)` | 1 |
| `newexpr` | `&v` in a pointer helper → `new(v)`; the helper was then inlined and deleted | 1 |
| `forvar` | redundant `x := x` loop copies (no-op under per-iteration loop variables) | several tests |
| `plusbuild` | removed the last obsolete `// +build` lines | 3 |

Counts overlap: one file can carry several rewrites. This pass changed 64 files
(+184/−230). The follow-up sweep in [Beyond the modernizers](#beyond-the-modernizers)
then touched 21 more Go files (+70/−91).

Two follow-ups were needed beyond what `go fix` emitted directly:

- `go fix` turned a membership closure into a one-line `slices.Contains` wrapper,
  which `gocritic`'s `unlambda` check then rejects. The closure was removed and its
  call sites use `slices.Contains` directly.
- `unparam` found dead results and parameters on top of the `go fix` output:
  `(*reloadManager).queueReloadRequest`'s `bool`, `(*reloadManager).refreshPprofServer`'s
  unused `log`, and `(*runtimeSupervisor).rollbackPrepared`'s two return values.
  A stale doc comment above `(*Dialer).check` (a leftover from the removed
  exported `Check` wrapper) was corrected in the same pass.
- Seven touched files predated the repo's SPDX header policy. The changed-file
  gate (`hack/maintenance/append_license_signature.sh --check`) covers every `.go`
  file a change touches, so those files received the standard header in this pass.

## Beyond the modernizers

`go fix` does not cover everything. A wider linter sweep (`unparam`, `errorlint`,
`wastedassign`, `makezero`, `usestdlibvars`) plus a manual read of the error paths
produced these additional changes:

- **Latent panic fixed.** `component/outbound/dialer/connectivity_check.go` used
  `if errAs(...); netErr.Timeout() {` — the `;` form discards the `errors.As`
  result, so a `net.Error` target left nil by a failed match was dereferenced.
  Any connectivity-check error that is not a `net.Error` panicked. It is now
  `if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {`.
- **`errors.AsType` adopted** (Go 1.26) at the sites where it removes a
  pre-declared target variable, including `trace/trace.go`, `cmd/dae-ebpf-audit`,
  `control/dns.go`, `control/dns_listener.go`, `control/control_plane.go`,
  `control/tcp_sniff_policy.go`, `control/udp_lifecycle.go`,
  `control/udp_endpoint_lifecycle.go`, `control/anyfrom_pool.go`,
  `component/sniffing/sniffer.go`, and `component/dnstransport/owned_conn.go`.
  Two kinds of site were deliberately left on `errors.As`:
  `common/errors/errors.go`, where a `err.(net.Error)` type assertion is an
  intentional hot-path fast path ahead of the `errors.As` fallback (the comments
  say so), and predicates whose whole body is `return errors.As(...)`, where
  `AsType` would need an extra `_, ok :=` line for no gain.
- **Dead stores removed** in `control/tcp.go`: `offloaded`, `offloadReason`, and
  `annotateOffload` were initialized to zero values and then unconditionally
  overwritten before any read.
- **`errors.Is` consistency.** `control/dial.go` compared
  `err == ob.ErrNoAliveDialer` while four sibling call sites already used
  `errors.Is`; a wrapped sentinel would have silently skipped the IP-version
  fallback. `control/anyfrom_pool.go` and
  `component/outbound/dialer/connectivity_check.go` had the same `==` shape for
  `unix.EIO`/`EINVAL` and `ErrNoApplicableIP`.
- **`http.MethodGet`** replaces the `"GET"` literal in
  `common/subscription/subscription.go`.
- **Test fixtures.** Unused results were dropped from `buildLargeDNSResponse` and
  `cacheAddressAnswer`; an unused closure parameter in
  `control/udp_task_pool_order_test.go` was removed, which also made the
  surrounding `wg.Add(1)`/`go`/`defer wg.Done()` convertible to `wg.Go`. The dead
  `fullcone` parameter of `newDirectDialer` was removed — one caller passed
  `true` expecting an effect the helper never had (it always built full-cone
  fixtures), so the helper now says so in a comment.
- One ad-hoc finding was investigated and rejected: `makezero` flags
  `append(lengthPrefix, payload...)` in `control/dns_tcp_ingress_corpus_test.go`,
  but the two-byte prefix is intentionally part of the returned frame.

## Deliberately not applied

- `pkg/geodata/common.pb.go` — protoc-gen-go output. Generated files are not
  hand-edited; regenerate with an updated generator instead. `go fix` keeps
  reporting this file, and that is expected.
- `tmp/` — gitignored scratch, not part of the build.
- `unparam`'s remaining findings — `wrapReloadTimeoutError`'s `timeout` argument is
  passed explicitly at all four call sites to document the deadline being wrapped;
  `(*Dialer).check` uses its named `ok` result only inside the function, and
  dropping it from the signature would split the loop's assignment across a
  separate local; and the rest are constant-argument fixture knobs on test helpers
  (`installCorpusCache`'s `ttl`, `seedConnState`'s `state`,
  `newFactoryProxyEndpointDialer`'s `protocol`), which document the fixture shape.
- `prealloc` suggestions (12 sites) are allocation micro-optimisations, not dead
  code, and `component/sniffing`'s `start`/`indicatorLen` initialisers sit in
  hot loops where the current form reads better.
- `errorlint`'s `%v` → `%w` suggestions change which errors callers can unwrap and
  were left for a separate decision.

## Available but not yet used

- `runtime.SetDefaultGOMAXPROCS` (1.25) plus the container-aware default: since the
  runtime already derives `GOMAXPROCS` from the cgroup CPU quota, code should only
  read `runtime.GOMAXPROCS(0)` (as `control/routing_matcher_builder.go` and
  `component/routing/domain_matcher/ahocorasick_slimtrie.go` do) rather than pin it.
- `os.Root` (1.24) for path traversal confined to one directory tree. Relevant if
  config or asset path handling becomes a hardening target.
- `omitzero` (1.24) is not interchangeable with `omitempty`: `omitzero` omits zero
  struct and array values that `omitempty` keeps. The configuration path decodes
  through `jsoniter` (`common/json`), so a migration needs per-field review and
  cannot be applied blindly.
- `GoroutineLeakProfile` — behind `GOEXPERIMENT=goroutineleakprofile`; consumed via
  `pprof.Lookup("goroutineleak")`. The repo currently uses `go.uber.org/goleak` in
  `control/main_test.go` and `component/outbound/dialer/register_lifecycle_test.go`.
- `GOEXPERIMENT` is owned solely by the Makefile
  (`make -s print-goexperiment`): `newinliner,simd,heapminimum512kib,randomizedheapbase64`.
  Do not restate it in CI, Dockerfiles, or scripts; `scripts/check-build-env.sh`
  rejects copies. Note that `randomizedheapbase64` is already in the go1.26.8
  baseline experiment set (`internal/buildcfg`), so listing it is explicit rather
  than required. `JSONv2` is not enabled: it would not replace the `jsoniter`-based
  fuzzy decoding in `common/json`.

## Keeping it clean

`go fix -diff` exits non-zero when a fix is pending, so it can back a CI guard:

```bash
go fix -diff ./...
go fix -diff -tags dae_bpf_tests ./control/kern/tests/...
```

Expect `pkg/geodata/common.pb.go` (and, when present, `tmp/`) to remain in the
output. Compare results per tag set, since `go fix` reports stale diffs for files
the current tag set excludes.

## Verification run

Applied and verified with:

```bash
gofmt -l $(git diff --name-only -- '*.go')           # clean
go build -tags dae_stub_ebpf ./... && go vet -tags dae_stub_ebpf ./...
go build ./... && go vet ./...
go build -tags trace ./... && go vet -tags trace ./...
go vet -tags dae_bpf_tests ./control/kern/tests/...
golangci-lint run --build-tags dae_stub_ebpf ./...   # 0 issues (CI gate)
golangci-lint run ./...                              # 2 pre-existing SA1019, see below
go test -tags dae_stub_ebpf -count=1 ./...           # green
go test -race -tags dae_stub_ebpf -timeout 30m ./control/... ./component/... ./cmd/...
make ebpf-test                                       # green
make ebpf-lint && make ebpf-sync-check               # clean
./hack/maintenance/append_license_signature.sh --check <changed .go files>
bash scripts/check-markdownlint-baseline.sh <markdownlint log>   # 0 new
npm run check-broken-link
```

`make ebpf-test` runs for real: the `dae_bpf_tests` bindings generate, the kernel
datapath suite passes, and the stubbed `dae_stub_ebpf` run is not treated as
evidence for it.

The two `golangci-lint run ./...` findings are pre-existing and unrelated to this
pass: `control/bpf_utils.go:138,152` reference
`consts.UserspaceBatchUpdateFeatureVersion`, which carries a `Deprecated` marker
(Ftrace does not support ARM64). CI lints only the `dae_stub_ebpf` build, under
which `control/bpf_utils.go` is not compiled, so the finding is not currently
gated. Resolving it means changing the feature-gating logic, not the constant.
