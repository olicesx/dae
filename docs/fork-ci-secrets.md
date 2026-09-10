# Why the fork's CI still uses `secrets: inherit`

## Summary

`Build (Main)`, `PR Build (Preview)` and `Daily Build (Main)` call reusable
workflows that live in another repository (`daeuniverse/ci-seed-jobs`). Those
calls use `secrets: inherit`. An explicit two-key mapping is the wanted end
state, but it cannot be written today: the called workflows do not declare the
secrets they read, and GitHub rejects passing a secret a reusable workflow does
not declare.

This note records the verified evidence, the compensating controls, the rejected
alternative, and the condition that unblocks the change.

## Verified upstream facts

Checked against the pinned commit `5d0b8710ae2b7fcc2051e5e9379671c6662b278e`
(retrieved through the GitHub contents API, same content served by the raw URL):

| Called workflow | `on.workflow_call.secrets` | Secrets actually read |
|---|---|---|
| `.github/workflows/pre-actions.yml` | absent (only `inputs` and `outputs` are declared) | `secrets.GH_APP_ID`, `secrets.GH_APP_PRIVATE_KEY`, and `secrets.TELEGRAM_TO` / `secrets.TELEGRAM_TOKEN` on the notification path |
| `.github/workflows/dae-post-actions.yml` | absent | `secrets.GH_APP_ID`, `secrets.GH_APP_PRIVATE_KEY` |

GitHub's documented rule is that inheritance is what reaches undeclared
secrets: "If the secrets are inherited by using `secrets: inherit` in the
calling workflow, you can reference them even if they are not explicitly
defined in the `on` key" ([Reuse
workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)).
Passing a named secret that the called workflow does not declare instead fails
workflow validation with `Invalid secrets: ... are not defined in the referenced
workflow`, which would break every build, pull request build and daily build.

## Rejected alternative: vendoring the wrappers

Copying the two upstream wrapper workflows into this repository was evaluated and
rejected. The wrappers are thin, but they must still invoke the upstream
composite actions (`common/report-workflow-run`, `common/report-check-run`) with
the same App credentials, so the secrets would reach exactly the same pinned
code. The security gain is close to zero, while the copy adds provenance and
drift surface. Pinning the commit (below) already bounds what that code can be.

## Compensating controls in place

| Control | Detail |
|---|---|
| Commit pinning | Every cross-repository reference is pinned to a 40-hex commit (`5d0b8710ae2b7fcc2051e5e9379671c6662b278e`); `.github/dependabot.yml` keeps that pin current |
| Minimal token permissions | The three callers declare workflow-level `permissions: contents: read`; no write scope is given to the automatic token |
| Explicit secrets where they are possible | The same-repository call to `./.github/workflows/seed-build.yml` passes `GH_APP_ID` / `GH_APP_PRIVATE_KEY` explicitly; `seed-build.yml` declares them under `workflow_call.secrets` |
| No `TELEGRAM_*` forwarding | The callers never set `notify: true`, so the upstream notification path is never handed those secrets |
| Renovation | `.github/dependabot.yml` (github-actions ecosystem) proposes pin updates, which are reviewed like any other change |

## Unblock condition

Once `daeuniverse/ci-seed-jobs` declares its `workflow_call.secrets`, replace
`secrets: inherit` with the explicit mapping in all six places and delete the
inline TODO comments:

| File | Jobs |
|---|---|
| `.github/workflows/build.yml` | `pre-actions`, `post-actions` |
| `.github/workflows/pr-build.yml` | `pre-actions`, `post-actions` |
| `.github/workflows/daily-build.yml` | `pre-actions`, `post-actions` |

## Verification

```shell
grep -rn 'secrets: inherit' .github/workflows | wc -l   # 6 today, target 0
```

The same grep is the acceptance check recorded for audit item P2-25.
