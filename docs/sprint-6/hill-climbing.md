# Sprint 6 Hill Climbing Report

> 生成：2026-08-04（QA 签署 PASS 后，orchestrator L4 自执行）
> Sprint 主题：稳定性 / bug fix 收割（**新 Sprint 类型** stability_hardening_allowed）
> **里程碑**：首次验证型 Sprint（产出是 gate pass 而非代码）+ 首次矿脉"零代码改动"收割（commits_used=1 纯 docs）+ 首次 WSL CRLF 污染事件 + 首次 fork 验证 gap 识别（OQ-S6-3）+ L19/L20 新 lesson，H11/H12 proposed

## Trace 聚合（6 Sprint 对比）

| 指标 | S1 | S2 | S3 | S4 | S5 | **S6** | 趋势 |
|------|----|----|----|----|----|--------|------|
| trace_count | 7 | 3 | 1 | ~11 | ~8 | ~15 | 验证型 Sprint trace 多（gate 逐项记录） |
| silent_failures | 0 | 0 | 0 | 0 | 0 | **0** | 持平（优） |
| goal_drifts | 0 | 0 | 0 | 0 | 0 | **0** | 持平（优） |
| l2_failures | 0 | 0 | 0 | 0 | 1 | **0** | S5 ci_gate 回归后 S6 无重蹈 |
| over_budget | 0 | 0 | 0 | 0 | 0 | **0 (1/3)** | 持平 |
| no_op_tasks | 57% | 33% | 0% | 0% | 0% | **0%（验证 task 无 no-op 概念）** | 验证型 Sprint 天然无 no-op |
| topology | serial | serial | serial | hybrid→seq | seq | **sequential** | 单 task |
| commits_used | 4/5 | 2/2 | 1/2 | 3/4 | 4/5 | **1/3（docs only）** | 首次"零代码"commit |
| **Sprint 类型** | perf | perf | perf | lifecycle | tech-debt | **stability_verification** | 首次验证型 |

## 新模式识别（Sprint 6 特有）

### 1. 首次验证型 Sprint —— scenario (a)/(b) 判定有效

T1 的 plan.md expected 预定义两种合法结果：(a) 全过=基线确认 / (b) 发现回归=捕获修复。实测命中 (a)。**验证型 Sprint 的"成功"不依赖代码产出**，而依赖 gate 覆盖完整性。

**lesson**：验证型 Sprint 的 feasibility_gate 不能用 G1/G2（liveness/heat），要用"验证覆盖度"判定（scope: race+ebpf+bench 覆盖全仓库）。plan.md 已正确自定义 `type: stability_verification`。

### 2. CRLF 污染 —— WSL drvfs 操作副作用（L19）

Dev 在 WSL（/mnt/c drvfs）跑 gate 时触发了 419 文件 CRLF 污染（全行替换 LF→CRLF）。`git diff --ignore-cr-at-eol` 确认纯 CRLF（只 PROJECT_BRIEF + .gitmodules.d.mk 有真实内容变更）。

**根因**：WSL git 在 /mnt/c（drvfs）操作时，结合 Windows 的 autocrlf 设置，可能触发行尾重检测。这是用户记忆「WSL 仓库 git 操作纪律」的延伸——不仅 git 写操作，**任何 WSL 文件操作**都可能触发 CRLF。

**清理方法（已验证有效）**：① `git diff --ignore-cr-at-eol --stat` 识别真实变更；② 备份真实变更文件（cp /tmp）；③ `git checkout -- .` 清除 CRLF；④ 恢复备份 + `sed -i 's/\r$//'` 去 CR。

**改进方向（H11 候选）**：Dev WSL 操作后，orchestrator Observe 强制检查 `git diff --ignore-cr-at-eol --stat`，若大量文件纯 CRLF 则自动清理。

### 3. commits_used 计数偏差（L20）

Dev 在 progress.md 写 `commits_used: 0`（scenario a，0 代码回归），但实际有 1 个 docs commit（149b3ce9）。Dev 的心智模型是"commits_used 只计代码 commit"。

**澄清**：commit_budget 管所有 commit（docs + code + 配置）。docs commit 也消耗 commit_budget。orchestrator L2 已修正为 commits_used=1。

**lesson（L20）**：commits_used = 所有进入 Sprint 范围的 commit（不论 docs/code）。Dev 记录时不应排除 docs commit。

### 4. Producer repo memory 工具认知（非 silent failure）

Producer claim 建立 `/memories/repo/{lessons-learned,harness-backlog}.md`。orchestrator Observe 时 `list_dir c:\Users\37112\memories\repo` 报 ENOENT（文件系统路径不存在），但 `memory view /memories/repo/` 成功（虚拟路径）。

**认知 gap**：memory 系统是虚拟的（memory 工具访问），不是文件系统路径。子 agent（Producer）用 memory 工具写入成功，但 orchestrator 用 list_dir（文件系统工具）验证失败。这不是 Producer silent failure，是工具认知不一致。

**对策**：验证 memory 文件用 `memory view`，不用 `list_dir`/`file_search`。

### 5. fork 验证 gap（OQ-S6-3，用户关切）

dae replace 引用 olicesx/outbound sticky-ip c5b8ecc + olicesx/quic-go dff8aaa5（非各自 main）。游离 commit 多次 bump fork（GSO/pooling/sticky-ip）。**fork 代码在 dae 测试盲区**——dae gate pass ≠ fork 代码正确。

**用户决策**：本地 checkout 对齐（outbound→c5b8ecc, quic-go→dff8aaa5, detached）。dae 编译仍走远程（无 go.work）。

**改进方向（H12 候选）**：跨仓库验证 harness——对 fork 依赖跑 fork 自己的测试（outbound/quic-go 仓库的 go test），纳入 Sprint gate。

## H1-H12 Eval 对照（6 Sprint 复利）

| 改进项 | 引入 | 应用 | S6 验证 |
|--------|------|------|---------|
| H1 ci_gate 探测 | S1 | S2-S6 | ✅ make ebpf-test 本机 runs |
| H3 脚本化 | S1 | S2-S6 | ✅ tmp/sprint6-*.sh 全程 |
| H4 关联文件 | S1 | S2-S6 | ✅ drift-check §0 游离 commit 机械关联 |
| H5 bench+memprofile | S2 | S3-S6 | ✅ bench H8 对照（非 mem，验证型无 memprofile） |
| H6 fidelity 语言无关 | S3 | S4-S6 | ✅ 按扩展名 .go + .c（eBPF） |
| H7 CPU profile | S4 | S4-S6 | conditional（非 CPU 主题，race 旁证） |
| H8 bench harness deadline | S4 | S5-S6 | ✅ bench H8 精确匹配（HTTP=5/TLS=6/NotApp=3） |
| H9 target_files 重叠检测 | S4 | S5-S6 | ✅ 单 task 无重叠 |
| H10 deletion_protection 增强 | S5 proposed | — | deferred（S6 不涉删除） |
| **H11 CRLF 污染检查** | **S6 proposed** | — | 🟡 candidate（Dev WSL 操作后 Observe 检查） |
| **H12 fork 验证 harness** | **S6 proposed** | — | 🟡 candidate（跨仓库测试纳入 gate） |

## 矿脉评估：验证型矿脉有效但"产出密度"不同

S6 收割 1 个验证 task（23 commit 权威验证），**0 代码改动**。与 S1-S5（代码改动型）不同，验证型 Sprint 的产出是"确认/信心"而非"代码行"。

| Sprint | 矿脉 | 产出 | commit |
|--------|------|------|--------|
| S1-S3 | Go alloc 优化 | 代码减分配 | 多 |
| S4 | lifecycle 重构 | 代码重构 | 3 |
| S5 | tech-debt cleanup | 测试瘦身+CPU 算法 | 4 |
| **S6** | **stability verification** | **gate pass + 信心** | **1（docs）** |

**洞察**：验证型 Sprint 是"必要的零产出"——在重大变更（23 游离 commit 含拆分）后确认稳定性。ROI 体现在"避免未发现的回归"，非代码增量。

## Sprint+1 候选

| 候选 | 来源 | 性质 | ROI |
|------|------|------|-----|
| fork 验证 harness（H12） | OQ-S6-3 | 新验证 Sprint | 中（fork 代码首次独立验证） |
| Makefile 上游 bug 修复（OQ-S6-4） | L4 发现 | 上游贡献 | 低（上游 Issue，非本 fork） |
| 巨型文件拆分后续 | S6 确认拆分无盲区 | 后续优化 | 中（拆分已 done，可优化拆分后结构） |
| 新功能/新方向 | 用户决定 | — | — |

## Harness backlog 更新

- **H10** 🟡 deferred（S6 不涉删除，适用条件不满足）
- **H11** 🟡 proposed（S6 L4）：Dev WSL 操作后 Observe 检查 CRLF 污染
- **H12** 🟡 proposed（S6 L4）：fork 依赖跨仓库验证 harness

## 跨 Sprint 复利总结（6 Sprint 数据点）

| 维度 | 演进 |
|------|------|
| Sprint 类型 | perf(S1-3) → lifecycle(S4) → tech-debt(S5) → **stability_verification(S6)** |
| no-op 率 | 57%→33%→0%→0%→0%→**0%（验证型天然无 no-op）** |
| harness 改进 | H1-H4 → H1-H8 → H1-H10 → **H1-H12**（+H11/H12 proposed） |
| lessons | L1-L17 → **L1-L20**（+L19 CRLF 清理, +L20 commits 计数） |
| L2 retry | S5 首次 → **S6 无**（H10 候选虽 deferred，但 S5 教训内化） |
| 重大变更应对 | — → **S6 首次"事后验证"型**（游离 commit 既成事实 → 权威验证基线） |

**Nadella 复利效应实证（6 Sprint）**：harness 从 0 成长到 H1-H12，lessons 从 0 到 L1-L20，Sprint 类型从单一 perf 到 4 种（perf/lifecycle/tech-debt/stability）。每次矿脉切换暴露新 failure mode（S5 删除盲区 → S6 CRLF 污染 + fork gap），harness 持续进化。
