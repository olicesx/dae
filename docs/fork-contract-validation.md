# Fork contract validation

The consumer and transport changes form one release unit. Runtime source changes
are in dae, outbound, and the local quic-go audit branch; qpack does not need a
version change for these repairs.

## Contracts

- TUIC serializes dial attempts, but callers can cancel while waiting for the
  client ring. A cancelled attempt must not create a UDP association or continue
  failover.
- Local destination validation errors do not retire a shared TUIC client. A
  genuine client retirement publishes `TransportDone` immediately and prevents
  further association writes. The existing physical-close grace period remains.
- `OwnedEarlyConn` closes its caller-owned packet connection on both explicit
  close and natural QUIC shutdown. These paths share one `sync.Once`; a request's
  cancellation is not a shared session shutdown.
- `TransportLifecycle` describes logical lifetime, not deadline behavior.
  `netproxy.WriteDeadlineBehavior` separately declares association-closing write
  deadlines. An adapter delegating `SetWriteDeadline` must preserve that behavior
  declaration; an adapter providing its own deadline semantics declares its own
  behavior.

## Test the working copies together

The local module graph selects the synchronized quic-go and outbound revisions.
Those revisions are local-only until their commits are published, so a clean
remote checkout cannot fetch these pseudo-versions yet. Testing outbound alone,
or testing dae against a previous remote pin, does not validate the changed pair.
Use a temporary modfile from the dae directory when exercising the working copies:

```bash
validation_dir="$(mktemp -d)"
cp go.mod "$validation_dir/go.mod"
cp go.sum "$validation_dir/go.sum"
go mod edit -modfile="$validation_dir/go.mod" \
  -replace="github.com/daeuniverse/outbound=$(realpath ../outbound)" \
  -replace="github.com/olicesx/quic-go=$(realpath ../quic-go)"
export GOFLAGS="-modfile=$validation_dir/go.mod"
export GOWORK=off

go list -m -json github.com/daeuniverse/outbound github.com/olicesx/quic-go

go test -mod=readonly -short -tags dae_stub_ebpf ./...
go test -mod=readonly -race -short -tags dae_stub_ebpf \
  ./control/... ./component/... ./cmd/...
go test -mod=readonly -race -short \
  github.com/daeuniverse/outbound/... \
  github.com/olicesx/quic-go \
  github.com/olicesx/quic-go/http3 \
  github.com/olicesx/qpack

go vet ./...
```

Real-datapath vet requires existing generated eBPF objects, or generation with
the repository toolchain. Run both fork's own tests and race suites from their
working directories as well, without the dae-specific `GOFLAGS` override:

```bash
(
  cd "$(realpath ../outbound)"
  env -u GOFLAGS -u GOWORK go test -mod=readonly -race ./...
)
(
  cd "$(realpath ../quic-go)"
  env -u GOFLAGS -u GOWORK go test -mod=readonly -race ./...
)
```

Once finished, unset `GOFLAGS` and `GOWORK` and remove the temporary validation
directory.

Run `golangci-lint run --timeout=10m --build-tags=dae_stub_ebpf` against the final
remote pin, using a linter built with Go 1.26 or later. For lint before publication,
use an isolated copy with the local replacement in its main go.mod: linter
package loaders do not necessarily propagate an external `-modfile` correctly.

## Local synchronization and release ordering

1. Advance the local quic-go pin to the reviewed quic-go revision.
2. Advance outbound's require/replace and checksums to that quic-go revision.
3. Advance dae's direct requires, replacements, and checksums to the synchronized
   outbound and quic-go revisions.
4. Validate both forks with the modified consumer together.
5. Publish the reviewed outbound and quic-go revisions through the normal release
   process, then confirm the same pseudo-versions are fetchable from the remote
   module proxy before release.
6. Rerun both the consumer-graph and standalone-fork CI gates at the final pins.

The new consumer references `netproxy.WriteDeadlineClosesSession`, so it must not
be released with an older outbound pin lacking that helper. Local pseudo-pins are
for this synchronized workspace only; a release must not rely on local paths,
local module caches, or unpublished commits.

## CI coverage

`Fork Regression` runs dependency package tests from dae's module graph as well
as the existing exact-revision standalone fork tests. The two gates answer
different questions: compatibility of the deployed combination and correctness
of each fork under its own declared dependencies.

QPACK interoperability tests require a git submodule corpus unavailable in its
module zip. Keep those in the standalone gate, which initializes the submodule;
select the QPACK root package in the consumer gate.
