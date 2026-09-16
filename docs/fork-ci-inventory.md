# Fork CI inventory (2026-09-16)

## Summary

This fork carries 18 workflow files, plus one check that exists only at the
repository level. A workflow that cannot do useful work in a fork is not a
safety net: it is either a permanently red check, a silently skipped job, or a
green check nobody reads. This note lists, per workflow, what triggers it, how
often it has actually run here, and whether it can work in this fork at all, so
that the deletion decision is made from evidence rather than from the file list.

Data source: the GitHub Actions API for `olicesx/dae`, read on 2026-09-16 —
`/actions/workflows` for the list and state, then
`/actions/workflows/{id}/runs?per_page=5` per workflow. "Runs" is this fork's own
lifetime count, not upstream's.

## Inventory

| Workflow | File | Trigger | Runs here | Last run | Can it work in this fork? |
|---|---|---|---|---|---|
| Build (Main) | `build.yml` | push `main`/`kdae`, Go/Makefile paths | 325 | 2026-09-16 success | Yes — source of the deployed artifacts |
| Go Test | `go-test.yml` | pull_request, push | 360 | 2026-09-16 success | Yes |
| Kernel Test | `kernel-test.yml` | pull_request, push | 395 | 2026-09-16 success | Yes |
| Lint | `lint.yml` | pull_request, push | 367 | 2026-09-16 success | Yes |
| eBPF Audit | `ebpf-audit.yml` | dispatch, pull_request, push | 372 | 2026-09-16 success | Yes |
| BPF Test | `bpf-test.yml` | pull_request, push | 240 | 2026-09-16 success | Yes |
| Fork Regression | `fork-cross-repo.yml` | pull_request, push, dispatch | 35 | 2026-09-15 success | Yes — the fork-pin contract harness |
| Docker | `docker.yml` | dispatch, push `main`/`kdae` (kern/Makefile/Dockerfile paths) | 18 | 2026-09-15 success | Builds yes; publish never (a fork holds no DockerHub credentials) |
| Synchronize Documents | `sync-docs.yml` | dispatch, push (docs paths) | 12 | 2026-09-15 success | Partly — the `dae-docs` sync job is gated off in forks |
| Check Documents | `check-docs.yml` | dispatch, workflow_call, pull_request | 2 | 2026-08-22 action_required | Yes — the docs gate itself |
| Build | `seed-build.yml` | workflow_call | 0 | never | Yes — reusable, invoked by `build.yml`, `pr-build.yml`, `daily-build.yml` |
| PR Build (Preview) | `pr-build.yml` | pull_request (Go paths) | 61 | 2026-08-26 failure | Yes, but unused and currently red |
| Daily Build (Main) | `daily-build.yml` | `schedule: 0 16 * * *` | 0 | never | **No** — GitHub disables schedules on forks (`disabled_fork`) |
| Generate Changelogs | `generate-changelogs.yml` | dispatch | 0 | never | **No** — needs the upstream App credentials this fork does not hold |
| Publish Pre-release | `prerelease.yml` | dispatch | 0 | never | Not used — the fork distributes via `Build (Main)` artifacts |
| Publish Release | `release.yml` | dispatch | 0 | never | Not used — same reason |
| Trigger downstream sync workflow | `trigger-downstream-flake-sync.yml` | dispatch, push `main` | 3 | 2026-02-13 failure | **No** — dispatches to a downstream repo that does not exist under this owner, with App credentials the fork does not hold |
| Copilot code review | *(no file)* | dynamic | 4 | 2026-03-13 failure | Repository-level check; disabling is a settings action, not a deletion |

## Deletion candidates

Each of these is either impossible in a fork or has never run; deleting one does
not remove any gate that currently protects the `kdae` branch.

1. **`daily-build.yml`** — the cron trigger is inert here: GitHub reports the
   workflow in state `disabled_fork`, and it has 0 runs. Its pre/post actions
   also read `GH_APP_ID` / `GH_APP_PRIVATE_KEY`, which this fork does not hold,
   so even a manual run would fail before the build starts.
2. **`generate-changelogs.yml`** — dispatch-only (0 runs) and built on the
   upstream App credentials (`secrets.GH_APP_ID`, `secrets.GH_APP_PRIVATE_KEY`)
   plus `daeuniverse/changelogs-generator-action` opening an issue. Upstream
   release tooling, unreachable from this fork.
3. **`prerelease.yml`** and **`release.yml`** — both dispatch-only (0 runs).
   This fork has never published a GitHub release: deployment consumes the
   `Build (Main)` artifact directly. Their publish paths also assume the
   upstream repository identity.
4. **`trigger-downstream-flake-sync.yml`** — dispatch-only plus push to `main`
   (the development branch here is `kdae`, so the push trigger never fires). It
   dispatches `sync-upstream.yml` in the repository named by
   `DOWNSTREAM_REPO: flake.nix` under the *same owner* — i.e. it would need a
   `flake.nix` repository to exist beside this fork — using an App token the
   fork does not hold. 3 runs, the last one failed on 2026-02-13.

## Needs a decision (not obviously dead)

- **`pr-build.yml`** — 61 runs, and the last one (2026-08-26) **failed**. Its
  value is a preview artifact per pull request. If this fork's development does
  not go through pull requests, those 61 runs produced nothing anyone consumed;
  if it does, the right move is to fix it rather than delete it.
- **`docker.yml`** — deliberately fork-adapted: the credentials are probed once,
  the multi-arch build always runs, and the publish step is skipped when there is
  nothing to publish with. So it is not dead — it is a Dockerfile build check
  whose most useful half (publishing) never executes here.
- **`sync-docs.yml`** — in this fork the `sync-to-dae-docs` job is already gated
  off (`if: github.repository != 'daeuniverse/dae'`). What remains is the
  `check-docs` gate, which already runs on pull requests via `check-docs.yml`,
  plus an artifact upload whose glob points at `./docs/sync/*.md` — a directory
  that does not exist, because the generator writes `hack/sync/example-config.md`
  (the workflow comment records this). Either slim it to the check or drop it.

## Kept, with the reason

- `build.yml` — the deployment line's artifact source; deleting it removes the
  ability to deploy a verified binary.
- `seed-build.yml` — reusable build body; `build.yml` calls it, so it is load
  bearing even at 0 self-attributed runs.
- `bpf-test.yml`, `go-test.yml`, `kernel-test.yml`, `lint.yml`,
  `ebpf-audit.yml` — the five gates, 240–395 runs each, all green on the current
  `kdae` head.
- `fork-cross-repo.yml` — resolves the `go.mod` replace pins and runs the fork's
  own tests; the only check that validates the three-layer fork chain.
- `check-docs.yml` — markdownlint ratchet, autocorrect, and broken-link checks;
  also the reusable workflow `sync-docs.yml` calls.

## Notes

- A Go-touching commit on `kdae` reports 41 check runs. A commit that only
  changes workflow files reports 10, because the path filters suppress the rest.
  A green subset is therefore not evidence that the whole CI passed — the
  count has to be read alongside the paths that changed.
- `Copilot code review` cannot be removed by deleting a file. It is a
  repository-level check (4 runs, last failure on 2026-03-13) and is switched
  off in repository settings.
