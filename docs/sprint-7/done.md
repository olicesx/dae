---
sprint: 7
sprint_theme: "Harness completion (H10 + H12 applied) / harness 完备化"
status: done
verdict: PASS
head_commit: pending
qa_signoff: self (CEO direct mode)
commits_used: pending
commit_budget: 3
constraint_policy: harness_hardening_allowed
branch: kdee
closed_at: 2026-08-05
---

# Sprint 7 Done — Harness 完备化（H10 + H12 首次应用）

> Sprint 7 是**首次 harness 主题 Sprint**（harness_hardening_allowed）。产出是两个长期资产脚本，0 源码改动。
> 这是 CEO 直接编排（用户授权 "你自己决断"），跳过 /kixpower-new 的 Producer 阶段（决策已由主对话完成），保留 dev + QA 自验。

## 目标回顾 / Goals Recap

- **T1（H10）**：deletion_protection gate 增强 —— 扫 Makefile + .github/workflows + scripts，防止 Sprint 5 ISSUE-1 类（bpf_bug_verification_test.go 被误删）重蹈
- **T2（H12）**：fork 依赖跨仓库验证 harness —— 对 dae replace 引用的 fork commit 跑 fork 自己的测试，覆盖 fork 改动盲区（OQ-S6-3 用户关切）

## 实际产出 / Actual Outcome

| 产出 | 文件 | 验证 |
|------|------|------|
| T1 脚本 | [scripts/deletion-protection-scan.sh](../../scripts/deletion-protection-scan.sh) | 红绿全过 |
| T2 脚本 | [scripts/fork-cross-repo-test.sh](../../scripts/fork-cross-repo-test.sh) | dry-run + 全量 advisory |
| tmp 辅助 | tmp/sprint7-*.sh | smoke/gate/fail-isolate/build-check（不入仓） |

### Sprint Gate 全过

| Gate | 结果 | 证据 |
|------|------|------|
| go_vet | ✅ pass | `go vet ./...` EXIT=0 |
| go_build | ✅ pass | `go build -tags=$(cat .build_tags) ./...` EXIT=0 |
| go_test_control | ✅ pass | control + component 全 ok（9.7s） |
| ebpf_lint | ✅ pass | tproxy.c / bpf_test.c / trace.c 0 style 问题 |
| T1_smoke_RED | ✅ pass | ISSUE-1 案例 → 4 hits + exit 1（Makefile:136/151/166/181） |
| T1_smoke_GREEN | ✅ pass | 不存在文件 → 0 hits + exit 0 |
| T1_edge_tproxy | ✅ pass | tproxy.c → 2 hits（Makefile EBPF_LINT_SOURCES + ebpf-audit.sh），正确保护非删目标 |
| T2_dry_run | ✅ pass | 正确解析 quic-go@dff8aaa58e14 + outbound@c5b8ecc17ecc |
| T2_full_advisory | ✅ pass | advisory 模式：12m16s 跑完，fork 测试 1 失败（quic-go）但 exit 0（详见 OQ-S7-1） |

## T2 关键发现（H12 价值证明）

**fork quic-go @ dff8aaa5 在自身测试套件中有 4 处失败**：

| 测试 | 性质 | 处置 |
|------|------|------|
| TestSendConnSendmsgFailures | WSL2 特权限制（sendmsg EPERM） | 环境，非 fork bug |
| TestSendStreamCloseForShutdown | mock 期望不匹配 | fork 维护者评估 |
| TestDatagramLoss + panic | datagram pool 改动可能引入 | fork 维护者评估 |
| TestConstantDelay | integrationtests/tools/proxy | fork 维护者评估 |

**这正是 H12 的价值**：dae 正在用 fork commit `dff8aaa5`，dae 自己的 gate 全过，但 fork 仓库自己的测试有失败 —— 没有 T2 之前完全不可见。T2 advisory 模式让 Producer 看到信号但不阻塞 dae Sprint。

## 实现要点 / Implementation Notes

### T1 自引用陷阱（已修复）
首版 T1 脚本扫描 `scripts/*.sh` 时，扫到自身注释里提到的 `bpf_bug_verification_test.go`（背景说明），导致 ISSUE-1 案例报 5 hits（应为 4）。修复：在搜索循环中跳过 `$(basename "$0")` 自身。

### T2 GOPROXY 必要性（新 lesson L21）
fork 仓库有独立 go.mod + 独立依赖（golang.org/x/net 等），可能不在 dae GOMODCACHE。WSL 默认网络访问 golang.org 超时（i/o timeout）。脚本默认 `export GOPROXY=https://goproxy.cn,direct`（尊重环境覆盖），同 Sprint 6 L18a 用 gh-proxy 解决 github.com 直连的模式。

### T2 advisory vs strict 设计
默认 advisory（exit 0）：fork bug 不阻塞 dae Sprint（fork 修复是独立工作）。`--strict` 用于 fork bump 决策时（Producer 评估新 fork commit 是否可引入）。

## L4 Hill Climbing 摘要

- **报告**：[docs/sprint-7/hill-climbing.md](hill-climbing.md)
- **新 lesson**：L21（fork deps 下载需 GOPROXY，L18a 同模式）
- **H 状态变化**：H10 + H12 从 🟡 pending 升级为 ✅ applied
- **里程碑**：首次 harness 主题 Sprint + H10/H12 双 harness 首次应用 + CEO 直接编排（跳过 /kixpower-new Producer）+ T2 首次捕获 fork 已有 bug（H12 价值实证）

## OQ 处置

| OQ | 处置 |
|----|------|
| OQ-S7-1（fork quic-go 4 处测试失败） | **留 fork 维护者** — 不属 dae Sprint 范畴，T2 advisory 已捕获，fork 修复后再次 bump 时复核 |

## 关键文档索引

| 文档 | 用途 |
|------|------|
| [docs/sprint-7/plan.md](plan.md) | task DAG T1/T2 + gates + OQ |
| [docs/sprint-7/hill-climbing.md](hill-climbing.md) | L4 报告 + L21 + H10/H12 应用证据 |
| [docs/sprint-7/runtime-context.md](runtime-context.md) | WSL + fork 仓库基线状态 |
