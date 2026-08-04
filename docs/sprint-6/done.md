---
sprint: 6
sprint_theme: "Stability / bug fix harvest (new sprint type) / 稳定性 / bug fix 收割"
status: done
verdict: PASS
head_commit: 149b3ce9
qa_signoff: docs/qa/qa-signoff-6.md
commits_used: 1
commit_budget: 3
constraint_policy: stability_hardening_allowed
branch: kdae
closed_at: 2026-08-04
---

# Sprint 6 Done — 稳定性 / bug fix 收割（新 Sprint 类型）

> Sprint 6 是**首次验证型 Sprint**（stability_hardening_allowed）。产出是 gate pass + 信心，非代码增量。对 23 个游离 commit（Sprint 5 外的未编排工作）补齐权威验证基线。

## 目标回顾 / Goals Recap

- **T1**：23 个游离 commit（722b123b..1ddfd8fb）权威验证基线 + 回归修复
  - 含：巨型文件拆分（dns_control→6 / udp_endpoint_pool→3 / run.go→4）+ 5 bug fix（dns TC bit / sniffing nil guard / roll method / dns UDP black-hole / dae DNS group override）+ perf（idle janitors event-driven）+ 多次 fork bump（GSO/buffer race/pooling/sticky-ip）
  - 59 files / +8608 / -7018

## 实际产出 / Actual Outcome

**Scenario (a) 命中**：10/10 gate pass，0 回归。

| Gate | 结果 | 证据 |
|------|------|------|
| go_vet / go_build / go_test | ✅ pass | WSL linux 全量 EXIT=0 |
| go_test_race | ✅ pass | rc=0, 50.5s, 无 race（sniffer Close guard / janitor / udp pool 拆分并发验证） |
| ci_gate_make_ebpf | ✅ pass | rc=0, 7.7s |
| ci_gate_ebpf_test | ✅ pass | rc=0, 13.8s, 23 用例全 PASS（L16/L17 build-tag 门控） |
| ebpf_lint / ebpf_sync_check | ✅ pass | rc=0 |
| bench_no_regression | ✅ pass | H8 全匹配：SniffTcp HTTP=5/TLS=6/NotApp=3 allocs（零回归） |
| manual_make_da_validate | ✅ pass | make dae rc=0 + validate example.dae rc=0 |

**commits_used=1**（149b3ce9 纯 docs commit，0 源码改动），budget=3（hard_cap=10）。

**三通道验证**：Dev 跑全 gate → orchestrator L2 独立重跑 race + ebpf-test（rc=0）→ QA 独立重跑 ebpf-test + bench H8 抽检（精确匹配）。

## 验证型 Sprint 的意义

Sprint 6 是"必要的零产出"——在重大变更（23 游离 commit 含巨型文件拆分）后确认稳定性。ROI 体现在"避免未发现的回归"，非代码增量。验证型 Sprint 的 feasibility_gate 用"验证覆盖度"（非 G1/G2 liveness）。

## L4 Hill Climbing 摘要

- **报告**：[docs/sprint-6/hill-climbing.md](hill-climbing.md)
- **新 lesson**：L19（WSL drvfs 全局 CRLF 污染 + 清理流程）、L20（commits_used 含 docs commit）
- **新 harness 候选**：H11（Dev WSL 操作后 CRLF 检查）、H12（fork 依赖跨仓库验证 harness）
- **里程碑**：首次验证型 Sprint + 首次"零代码"commit + 首次 CRLF 污染事件处理 + 首次 fork gap 识别

## OQ 处置

| OQ | 处置 |
|----|------|
| OQ-S6-1（bug fix 同类边界） | **关闭** — T1 未发现真实未处理边界 |
| OQ-S6-2（拆分盲区） | **关闭** — ebpf-test + go test 全过，无盲区 |
| OQ-S6-3（fork 验证 gap） | 不阻塞，留 Sprint+1 候选（H12）；本地 checkout 已对齐（outbound→c5b8ecc sticky-ip, quic-go→dff8aaa5, detached） |
| OQ-S6-4（Makefile 上游 tr bug） | **待用户裁决** — 是否提 daeuniverse/dae 上游 Issue（不可逆外部操作） |

## 过程事件

- **CRLF 污染**：Dev WSL 操作触发 419 文件 CRLF 污染（LF→CRLF）。orchestrator Observe 识别（`git diff --ignore-cr-at-eol`），清理（备份 PROJECT_BRIEF → git checkout -- . → 恢复去 CR）。记 L19 + H11。
- **.gitmodules.d.mk**：Dev 手动修 Makefile 上游 bug 的 workaround 已 revert（生成产物不该手改）。记 OQ-S6-4。
- **依赖对齐**：用户关切 outbound/quic-go 引用非 main → 本地 checkout 对齐（detached at dae 引用的 fork commit）。

## 关键文档索引

| 文档 | 用途 |
|------|------|
| [docs/sprint-6/plan.md](plan.md) | task DAG T1 + verifiable_gates + constraint_policy |
| [docs/sprint-6/progress.md](progress.md) | Trace Log + gate 状态 + L2 Verification |
| [docs/sprint-6/drift-check.md](drift-check.md) | §0 既成事实基线（23 游离 commit）+ 4 项 drift |
| [docs/sprint-6/hill-climbing.md](hill-climbing.md) | L4 报告 + L19/L20 + H11/H12 |
| [docs/qa/qa-signoff-6.md](../qa/qa-signoff-6.md) | QA 签署 PASS（head_commit 149b3ce9） |
