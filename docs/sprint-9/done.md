---
sprint: 9
sprint_theme: "Architecture refactor: control_plane_core.go split / 架构重构：control_plane_core.go 拆分"
status: done
verdict: PASS
head_commit: pending
qa_signoff: self (CEO three-channel cross-check)
commits_used: pending
commit_budget: 5
constraint_policy: architecture_refactor_allowed
branch: kdae
closed_at: 2026-08-05
---

# Sprint 9 Done — control_plane_core.go 架构拆分

> Sprint 9 是 Sprint 8 模式的复用：CEO 委派 kixpower-dev 做实现，主对话三通道独立验证 + QA。control_plane_core.go 1409 → 625 行（-56%），0 逻辑改动。

## 目标回顾 / Goals Recap

- **T1**：拆 control/control_plane_core.go 到 2 个子系统文件（同 package control，机械性 mv，不改逻辑/签名/API）

## 实际产出 / Actual Outcome

| 文件 | 行数 | 函数数 | 内容 |
|------|------|--------|------|
| [control/control_plane_core.go](../../control/control_plane_core.go) | 1409 → **625**（-784） | 23 保留 | 全局 vars + controlPlaneCore struct + newControlPlaneCore + bpf hook lifecycle + Eject*/Peek/startIfindexWatcher |
| [control/control_plane_core_bind.go](../../control/control_plane_core_bind.go) | 644 | 14 | qdisc 工具（getIfParamsFromLink/buildClsactQdisc/addQdisc/delQdisc/linkHdrLen）+ bindLan/_bindLan + setup* + bindWan/_bindWan + bindDaens + registerInterfacePattern/attachMatchingInterfaces |
| [control/control_plane_core_routing.go](../../control/control_plane_core_routing.go) | 170 | 7 | deleteTCFiltersByHandle + extractIPsFromDnsCache + BatchUpdate/RemoveDomainRouting + Retain/Transfer/ReleaseUdpConnStateTuples |

**21 个函数移动，0 逻辑改动**（git numstat: `0 784` for control_plane_core.go）。

## 三通道独立验证

### Channel 1: 函数集合一致性
- 原 control_plane_core.go（Sprint 8 HEAD 8e9d1276）顶层 func 数：**44**
- 当前 3 文件合并顶层 func 数：**44**
- **FUNC_SET_MATCH**

### Channel 2: body-level 语义 diff
- 原 unique 非空行：1311；新合并：1335
- 37 行差异**全是机械副产品**：2 个新文件各自的 SPDX license 头 + `package control` 声明 + `import (` 块 + 重复 import 行（`"errors"`/`"fmt"`/`"os"`/`"github.com/cilium/ebpf"`/`"github.com/cilium/ebpf/link"`/`"github.com/vishvananda/netlink"`/`"golang.org/x/sys/unix"`）
- **无任何逻辑行差异**

### Channel 3: git diff --numstat
- control_plane_core.go: **0 add / 784 del**

## Sprint Gate 全过

| Gate | 结果 | 证据 |
|------|------|------|
| go_vet | ✅ pass | `go vet ./control/...` EXIT=0 |
| go_build | ✅ pass | `go build -tags=trace ./...` EXIT=0 |
| go_test_control_short | ✅ pass | control + component 全 ok |
| go_test_race_control | ✅ pass | `go test -race -short ./control/...` 10.876s EXIT=0（dev 跑） |
| make_ebpf_test | ✅ pass | 23 用例全 PASS（2.748s） |
| make_dae | ✅ pass | CLI build EXIT=0 |
| manual_make_da_validate | ✅ pass | `./dae validate -c /tmp/s9-test-config.dae`（0600 copy）EXIT=0 |
| ebpf_lint | ✅ pass | tproxy.c / bpf_test.c / trace.c 0 style 问题 |
| semantic_three_channel | ✅ pass | 44=44 函数 / body diff 只机械副产品 / 0-784 numstat |

## 实现过程要点

### dev 子代理（kixpower-dev）—— Sprint 8 模式复用
- **Python 脚本批量提取**：dev 写 `tmp/sprint9-split.py`，按 `^func` + `^}` 边界检测，提取 2 簇
- **off-by-one 陷阱**（dev 自报告 L22 候选）：首版 Python 脚本边界检测把 import 块的 `)` 误包含进函数体（import block `)` 在 L29 非 L28，body1 多了一个 `)`），被 `go build` + 内容断言即时捕获，从 git 恢复重做
- **三 seam byte-for-byte spot-check**：dev 对 3 个关键接缝（core Close→EjectBpf / bind bindDaens 尾 / routing 头尾）做了字节级比对

### 主对话独立验证（不靠 dev 自报告）
- 三通道系统化（函数集合 44=44 / body diff 37 行全机械 / numstat 0-784）
- 独立重跑 vet/build/race + e2e gate（ebpf-test/make dae/validate/ebpf-lint）

## L4 Hill Climbing 摘要

- **报告**：[docs/sprint-9/hill-climbing.md](hill-climbing.md)
- **新 lesson 候选 L22**：批量提取工具的边界检测——func 体边界（`^func` 到下个 `^}` 或 `^func`）vs import 块边界（`(` 到 `)`）不要混淆；go build 即时捕获。Sprint 8 import 误报（参数名匹配包名）+ Sprint 9 off-by-one（import `)` 误包含）都是"机械提取工具的边界检测陷阱"的实例。
- **里程碑**：Sprint 8 模式首次复用 + control_plane 系列拆分完成（plane + core 共 -1765 行，8 个新文件）

## OQ 处置

| OQ | 处置 |
|----|------|
| OQ-S9-1（control_plane_core.go 仍 625 行，是否继续拆） | **deferred** — 625 行可接受；剩余全是高内聚的 bpf hook lifecycle + 资源管理，强行拆会破坏内聚 |
| OQ-S9-2（dns.go 1273 / dns_controller_cache.go 1151） | **deferred** — Sprint 10 候选；需先看 dns.go 结构判断内聚性 |
| OQ-S9-3（dev Python 脚本是否沉淀为通用拆分工具） | **deferred** — Sprint 8/9 dev 各自重写 Python 脚本，说明沉淀有价值；若 Sprint 10 继续拆分，考虑沉淀 |

## 关键文档索引

| 文档 | 用途 |
|------|------|
| [docs/sprint-9/plan.md](plan.md) | constraint_policy + task DAG + gates + risks |
| [docs/sprint-9/progress.md](progress.md) | dev Trace Log（含 off-by-one 修复记录） |
| [docs/sprint-9/done.md](done.md) | 三通道验证证据 + 全 gate 结果 |
| [docs/sprint-9/hill-climbing.md](hill-climbing.md) | L4 报告 + L22 候选 + control_plane 系列总结 |
| [docs/sprint-9/runtime-context.md](runtime-context.md) | WSL 环境 + 三通道命令索引 |
