---
sprint: 8
sprint_theme: "Architecture refactor: control_plane.go split / 架构重构：control_plane.go 拆分"
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

# Sprint 8 Done — control_plane.go 架构拆分

> Sprint 8 是**首次架构重构 Sprint**（architecture_refactor_allowed）。CEO 委派 kixpower-dev 做实现，主对话做三通道独立验证 + QA。control_plane.go 4315 → 3334 行（-23%），0 逻辑改动，全 gate pass。

## 目标回顾 / Goals Recap

- **T1**：拆 control/control_plane.go（4315 行）到 4 个子系统文件（同 package control，机械性 mv，不改逻辑/签名/API）

## 实际产出 / Actual Outcome

| 文件 | 行数 | 函数数 | 内容 |
|------|------|--------|------|
| [control/control_plane_parse.go](../../control/control_plane_parse.go) | 85 | 4 | ParseFixedDomainTtl / ParseGroupOverrideOption / parseGroupOverrideOptionWithRuntime / inheritGroupOptionRuntime |
| [control/control_plane_dns.go](../../control/control_plane_dns.go) | 307 | 18 | DNS reload cache（9）+ DNS handoff controller（9） |
| [control/control_plane_datapath.go](../../control/control_plane_datapath.go) | 396 | 11 | listener socket publish（4）+ datapath commit/reload（7） |
| [control/control_plane_dialtarget.go](../../control/control_plane_dialtarget.go) | 259 | 9 | dial target + real domain probe |
| [control/control_plane.go](../../control/control_plane.go) | **3334**（原 4315，**-981**） | — | 瘦身：保留 ControlPlane struct + 构造函数家族 + bpf/dialer 基础访问器 |

**总计**：42 个函数移动，4 个新文件，0 逻辑改动（git numstat: `0 981` for control_plane.go）。

## 三通道独立验证（核心证据）

### Channel 1: 函数集合一致性
- 原 control_plane.go（Sprint 7 HEAD 0e5a74fc）顶层 func 数：**136**
- 当前 5 文件合并顶层 func 数：**136**
- **FUNC_SET_MATCH**（diff 空）

### Channel 2: body-level 语义 diff
- 原 unique 非空行：4005；新合并：4060
- 76 行差异**全是机械副产品**：4 个新文件各自的 SPDX license 头 + `package control` 声明 + 重复 import 行（`"context"`、`"fmt"`、`"github.com/cilium/ebpf"` 等）
- **无任何逻辑行差异**

### Channel 3: git diff --numstat
- control_plane.go: **0 add / 981 del** —— 纯删除，0 新增

三通道一致 → dev claim "0 逻辑改动" 独立验证通过。

## Sprint Gate 全过

| Gate | 结果 | 证据 |
|------|------|------|
| go_vet | ✅ pass | `go vet ./control/...` EXIT=0 |
| go_build | ✅ pass | `go build -tags=$(cat .build_tags) ./...` EXIT=0 |
| go_test_control_short | ✅ pass | control + component 全 ok（cached） |
| go_test_race_control | ✅ pass | `go test -race -short ./control/...` 10.967s EXIT=0 |
| go_test_race_sniffing | ✅ pass | `go test -race ./component/sniffing/...` EXIT=0 |
| make_ebpf_test | ✅ pass | 23 用例全 PASS（2.481s） |
| make_dae | ✅ pass | CLI build EXIT=0 |
| manual_make_da_validate | ✅ pass | `./dae validate -c /tmp/test-config.dae`（chmod 0600 copy）EXIT=0 |
| semantic_three_channel | ✅ pass | 136=136 函数 / body diff 只机械副产品 / 0-981 numstat |

## 实现过程要点

### dev 子代理策略（kixpower-dev）
1. **最小簇先验证工具链**：parse 簇（68 行）用 `replace_string_in_file` 手动提取，确认机制可行
2. **大簇用 Python 脚本批量提取**：dns/datapath/dialtarget 三簇（共 ~870 行）用 `tmp/sprint8-split.py`，按 `^func` + `^}` 边界检测，避免转录错误
3. **import 自动分析 + go build 校验**： qualifier 匹配有 3 处误报（`net`/`outbound`/`routing` 是参数名非包名），全部被 `go build` 捕获修复

### dev 发现并纠正 prompt typo
我派发 dev 时 prompt 写错函数名（`SharesActiveDnsController` 应为 `SharesActiveDnsControllerWith`）。dev 实际读代码发现并正确处理 —— **dev 子代理不盲目执行 prompt，会读代码纠错**。这是 AI 子代理可靠性的好信号。

### PowerShell `$?` 陷阱（L7 再次实证）
dev 在验证时遇到 PowerShell `$?` 被自身解析（返回 True/False 而非 bash exit code）。dev 自己学到并改用脚本文件（tmp/sprint8-*.sh）。L7 教训对外部 agent 也有效。

## L4 Hill Climbing 摘要

- **报告**：[docs/sprint-8/hill-climbing.md](hill-climbing.md)
- **无新 hard lesson**：拆分顺利，0 回归，无新 failure mode
- **里程碑**：首次架构重构 Sprint + 首次 CEO 委派 dev 子代理做大文件拆分 + 三通道语义验证首次系统化应用（函数集合 / body diff / numstat）

## OQ 处置

| OQ | 处置 |
|----|------|
| OQ-S8-1（control_plane_core.go 1311 行是否同模式拆） | **deferred** — Sprint 9 候选；core 已比 plane 紧凑（bpf hook + 接口绑定 + domain routing 三簇），1311 行可接受 |
| OQ-S8-2（dns.go 1273 / udp.go 1172 / dns_controller_cache.go 1151） | **deferred** — 后续 Sprint 评估；dns.go 内聚性可能高于 control_plane.go，需先看结构 |
| OQ-S8-3（dev 子代理的 Python 脚本是否沉淀为通用拆分工具） | **deferred** — 当前是一次性 tmp 脚本；若 Sprint 9+ 继续拆分，考虑沉淀到 scripts/ |

## 关键文档索引

| 文档 | 用途 |
|------|------|
| [docs/sprint-8/plan.md](plan.md) | constraint_policy + task DAG + gates + risks |
| [docs/sprint-8/progress.md](progress.md) | dev Trace Log（每簇提取细节 + 遇到的问题） |
| [docs/sprint-8/hill-climbing.md](hill-climbing.md) | L4 报告 + 三通道验证实证 + 矿脉评估 |
| [docs/sprint-8/runtime-context.md](runtime-context.md) | WSL 环境 + 关键命令索引 |
