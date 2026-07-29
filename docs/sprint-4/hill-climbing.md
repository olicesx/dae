# Sprint 4 Hill Climbing Report

> 生成：2026-07-29（QA 签署 PASS 后，orchestrator L4 自执行）
> Sprint 主题：嗅探生命周期重构 + CPU Profile 方法论（H7）
> **里程碑**：首次解除「语义等价」约束（constraint_policy: lifecycle_refactor_allowed）+ 首次引入 H7（CPU profile 第三维度）+ 首次拓扑降级（hybrid→sequential）

## Trace 聚合（4 Sprint 对比）

| 指标 | Sprint 1 | Sprint 2 | Sprint 3 | Sprint 4 | 趋势 |
|------|----------|----------|----------|----------|------|
| trace_count | 7 | 3 | 1 | ~11 | lifecycle 重构复杂度回升（预期） |
| silent_failures | 0 | 0 | 0 | 0 | 持平（优） |
| goal_drifts | 0 | 0 | 0 | 0 | 持平（优） |
| l2_failures | 0 | 0 | 0 | 0 | 持平（优） |
| over_budget | 0 (4/5) | 0 (2/2) | 0 (1/2) | 0 (3/4) | 持平（优） |
| no_op_tasks | 4/7 (57%) | 1/3 (33%) | 0/1 (0%) | **0/3 (0%)** | 持平（优） |
| harness-noise task | — | 1 (T2) | 0 | **0** | H5 持续 |
| topology_downgrade | 0 | 0 | 0 | **1 (hybrid→seq)** | 新信号（见下） |
| L2 retry | 0 | 0 | 0 | 0 | 持平（优） |

## H1-H7 Eval 对照（4 Sprint 复利趋势）

| 改进项 | 引入 | 应用 | Sprint 4 验证 |
|--------|------|------|--------------|
| H1 ci_gate 探测 | S1 L4 | S2-S4 | ✅ 持续 runs（make ebpf-test QA 实跑 PASS） |
| H2 bench 驱动 | S1 L4 | S2 | ⚠️ deprecated（H5 取代） |
| H3 脚本化 | S1 L4 | S2-S4 | ✅ 持续（全程 tmp/*.sh） |
| H4 关联文件 | S1 L4 | S2 | ✅ 持续 |
| H5 bench+memprofile | S2 L4 | S3-S4 | ✅ 持续（5 目标函数 flat 消除） |
| **H6 fidelity 语言无关** | S3 L4 | **S4** | ✅ **首次应用**（drift-check §4 按扩展名 git-log） |
| **H7 CPU profile 第三维度** | **S4 L4** | **S4** | ✅ **首次应用，强生效**（见下） |

### H7 生效证据（本 Sprint 核心）

- **Sprint 1-3（H7 前）**：仅 bench（H2/H5）+ memprofile（H5）两维度，只见「分配次数/大小」，不揭示「CPU 时间花在哪」
- **Sprint 4（H7 后）**：CPU profile 揭示 **GC 主导 CPU（gcBgMarkWorker 27% + mallocgc 14% + scan ≈ 41-50%）→ alloc 与 CPU 热点收敛**
- **收益闭环**：lifecycle 重构（砍每连接 Sniffer 分配）→ 降 GC 压力 → gcBgMarkWorker cum% 27.26%→10.84%（**-16pp**，QA 复现）
- **风险预判纠偏**：曾合理预判「CPU 与 alloc 热点可能不重合」（plan §风险预判 3），**实测重合**——用数据否定预判，这正是引入第三维度的价值（催生 L12）

### H6 生效证据

- verification-fidelity-check.ps1 原假设 `src/` 布局，对 Go 项目假阴性
- Sprint 4 应用：drift-check §4 改用按扩展名（.go/.c/.rs）git-log 权威方法，正确检出 control/component 下源码改动
- 残留改进（非阻塞）：`-SinceDate` 30 天窗口过宽，应按 Sprint 边界 commit range（记入 backlog 注释）

## 模式识别

### 1. 拓扑降级信号（Sprint 4 新现象）

plan.md 标 hybrid 拓扑（T1/T3 并行 → T2 串行），但 T1/T2/T3 三 task 共享 `component/sniffing/sniffer.go`，target_rules 无法互斥。orchestrator 按 kixpower「拓扑降级」规则降级为 sequential（顺序 T1→T3→T2）。

**lesson**：Producer 规划 DAG 时，拓扑选择不能只看逻辑依赖，**必须检查 target_files 物理重叠**。本 Sprint 的 hybrid 判断基于逻辑独立（T1/T3 无数据依赖），但忽略了文件级共享。**改进方向（候选 H9）**：Producer 的 task DAG 规划增加「target_files 重叠检测」——若多 task 共享文件，强制降级 sequential（或 worktree 隔离）。

### 2. 约束切换开启新矿脉

| Sprint | 约束 | 矿脉状态 |
|--------|------|---------|
| S1-S3 | semantic-preserving | 主→次→尾，S3 枯竭 |
| S4 | lifecycle_refactor_allowed | **丰饶**（T1/T2/T3 全有效，0 no-op） |

**关键洞察**：当矿脉在现有约束下枯竭（S3 hill-climbing 已明示），**切换约束 + 扩展方法论维度 = 开启新矿脉**。S4 同时做了两件事（解除约束 + 引入 H7），双击开启 lifecycle 重构矿脉。

### 3. cum%/flat% 相对值陷阱（L14）

lifecycle 重构后 GC 总量骤降 → 分母缩小 → APP 函数 cum% 相对上升（SniffTcp 9.49%→19.51% 看似回归，实际绝对时间微增）。判据须用「GC 类函数 cum% 是否下降」+ 绝对 alloc_objects，不可单看 APP 函数百分比。

## 矿脉评估：lifecycle 重构矿脉仍丰饶

Sprint 4 收割了 3 个 lifecycle 候选（Sprint 1-3 三次 deferred），全部 effective。剩余 lifecycle 方向：

| 候选 | 来源 | 性质 |
|------|------|------|
| 长驻 reader goroutine（消除 per-call spawn） | OQ-S4-1 保守方案残留 | lifecycle（触读语义风险，须谨慎） |
| sniffHTTPHostHeader + bytes.Index 纯 CPU | OQ-S4-3 | CPU 算法（非 lifecycle） |
| bench conn 改 deadline-supporting | L14 | harness 改进（H8 候选） |

## Sprint+1 候选（功能 backlog，非 harness）

- **长驻 reader goroutine**：T1 当前用「内联单 goroutine + channel 复用」（保守），可进一步用 per-Sniffer 长驻 goroutine 消除 per-call spawn。⚠️ 触 OQ-S4-1 读语义风险，须完整 race + 语义对照
- **sniffHTTPHostHeader + bytes.Index CPU 优化**：纯 CPU 计算热点（非分配驱动），属 CPU 算法优化方向，lifecycle 主题不覆盖
- **bench harness 路径代表性修复**：bytes.Reader→deadline-supporting conn，消除 async 偏差（催生 H8）

## Harness backlog 更新

- **H6** ✅ applied（Sprint 4）：fidelity 语言无关化
- **H7** ✅ applied（Sprint 4）：CPU profile 第三维度，强生效（gcBgMarkWorker -16pp）
- **H8** 🟡 proposed（Sprint 4 L4）：bench harness 路径代表性检测（来自 L14 async 偏差）
- **H9** 候选（未正式提案）：Producer task DAG target_files 重叠检测（来自拓扑降级信号）

## 跨 Sprint 复利总结（4 Sprint 数据点）

| 维度 | 演进 |
|------|------|
| no-op 率 | 57% → 33% → 0% → **0%**（H2+H5+H7 叠加，连续 2 Sprint 零 no-op） |
| harness 改进 | 0 → H1-H4 → H1-H5 → **H1-H8**（+H8 proposed, +H9 候选） |
| 方法论维度 | grep 静态 → bench 实测 → bench+memprofile → **bench+memprofile+CPU（三维度）** |
| 约束策略 | semantic-preserving（S1-S3）→ **lifecycle_refactor_allowed（S4）** |
| lessons | L1-L8 → L1-L9 → L1-L11 → **L1-L14**（+L12 CPU/GC 收敛、+L13 pool+goroutine 守卫、+L14 相对值陷阱） |
| 拓扑复杂度 | serial → serial → serial → **hybrid→sequential（降级）** |

**Nadella 复利效应实证（4 Sprint）**：harness 改进（H1-H8）每个都基于前序 Sprint 的失败模式或新发现，形成可量化的学习曲线。Sprint 4 的两个「首次」（解除约束 + H7 CPU 维度）证明：当矿脉在现有框架内枯竭时，**扩展框架本身**（约束 + 维度）比在旧框架内深挖更有效。论文证据「build learning loops early... advantage hard to replicate」在第 4 个 Sprint 继续得到验证——连续 2 Sprint 零 no-op、零 harness-noise task、零 L2 retry，且 H7 揭示了前 3 Sprint 完全无法看到的 GC-CPU 收益闭环。
