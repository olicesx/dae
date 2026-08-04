# Sprint 7 Hill Climbing Report

> 生成：2026-08-05（dev + QA 自验后，CEO 直接编排 L4 自执行）
> Sprint 主题：Harness 完备化（**新 Sprint 类型** harness_hardening_allowed）
> **里程碑**：首次 harness 主题 Sprint + H10/H12 双 pending → applied + CEO 直接编排（跳过 Producer）+ T2 首次实证 H12 价值（捕获 fork 已有 bug）+ L21 新 lesson（GOPROXY 必要性）

## Trace 聚合（7 Sprint 对比）

| 指标 | S1 | S2 | S3 | S4 | S5 | S6 | **S7** | 趋势 |
|------|----|----|----|----|----|----|--------|------|
| trace_count | 7 | 3 | 1 | ~11 | ~8 | ~15 | ~10 | harness Sprint，gate 逐项记录 |
| silent_failures | 0 | 0 | 0 | 0 | 0 | 0 | **0** | 持平（优） |
| goal_drifts | 0 | 0 | 0 | 0 | 0 | 0 | **0** | 持平（优） |
| l2_failures | 0 | 0 | 0 | 0 | 1 | 0 | **0** | 持平 |
| over_budget | 0 (4/5) | 0 (2/2) | 0 (1/2) | 0 (3/4) | 0 (4/5) | 0 (1/3) | **0 (TBD)** | 持平 |
| no_op_tasks | 57% | 33% | 0% | 0% | 0% | 0% | **0%** | 持平（连续 4 Sprint） |
| topology | serial | serial | serial | hybrid→seq | seq | seq | **parallel (T1/T2 独立)** | 首次并行 |
| commits_used | 4/5 | 2/2 | 1/2 | 3/4 | 4/5 | 1/3 | **TBD** | — |
| Sprint 类型 | perf | perf | perf | lifecycle | tech-debt | stability | **harness** | 首次 harness |

## 新模式识别（Sprint 7 特有）

### 1. CEO 直接编排有效（跳过 Producer）

用户授权"你自己决断"，主对话直接做 Producer 决策（主题/scope/DAG/验收）+ dev 实现 + QA 自验。Sprint 1-6 全走 kixpower 团队编排（producer → dev → qa），Sprint 7 验证了**轻量路径**：决策明确且 scope 小（2 个独立脚本，0 源码改动）时，CEO 自编排比团队编排更高效。

**适用判据**：scope ≤ 3 文件 + 0 源码逻辑改动 + 决策路径线性（无脑暴分歧）→ 可跳 Producer。下次同规模 harness Sprint 可复用。

### 2. T2 advisory 模式 —— fork bug 不阻塞 dae（H12 设计验证）

T2 首次跑全量暴露：fork quic-go @ dff8aaa5 在自己测试套件中有 4 处失败。**dae 正在用这个 commit**，dae gate 全过。

**关键决断**：fork bug ≠ dae bug。fork 修复是独立工作（fork 维护者范畴），不应阻塞 dae Sprint。T2 默认 advisory（exit 0 + 报告），`--strict` 用于 fork bump 决策。

**对比 strict 模式的反例**：如果 T2 默认 strict，Sprint 7 会被 fork 已有 bug 阻塞，但 dae 源码 0 改动 —— 这是"外部依赖的 bug 卡住自己 Sprint"的反模式。advisory 是正确选择。

### 3. T2 价值实证（H12 不是假设）

Sprint 6 提出 H12 时是"假设 fork 有 bug"。Sprint 7 首次应用捕获到 4 处真实失败（虽然 1 个是 WSL 环境限制，3 个是 fork 真 bug）。**这把 H12 从"防御性假设"升级为"已证实的覆盖率 gap"**。

**信号**：dae 引用的 fork commit 在它的测试套件里有 panic（`failed to parse short header: not a QUIC packet`）。这种 panic 在 dae 自己的 e2e 里可能从不触发（dae 不走那个代码路径），但**潜在风险存在**。H12 advisory 报告 = 早期信号系统。

### 4. T1 自引用陷阱（harness 设计盲区）

首版 T1 扫描 `scripts/*.sh` 时扫到自身注释里的 `bpf_bug_verification_test.go`（背景说明），导致红绿验证报 5 hits（应 4）。**harness 脚本本身的注释会污染扫描结果**。

**对策**：扫描循环跳过 `$(basename "$0")`。这是 harness 设计的元 lesson —— **任何 grep 类扫描脚本都要排除自引用**。

### 5. fork deps GOPROXY 必要性（L21）

fork 仓库有独立 go.mod + 独立依赖版本（golang.org/x/net v0.28.0 等），可能不在 dae 的 GOMODCACHE。WSL2 默认访问 golang.org 超时（i/o timeout）。**与 Sprint 6 L18a 同模式**（L18a：github.com 直连不稳 → gh-proxy 镜像；L21：golang.org 直连超时 → goproxy.cn 镜像）。

**lesson L21**：跨仓库 harness 必须考虑 fork 仓库的依赖下载环境。脚本默认 `export GOPROXY=https://goproxy.cn,direct`（尊重环境覆盖）。

## H1-H12 Eval 对照（7 Sprint 复利）

| 改进项 | 引入 | 应用 | S7 验证 |
|--------|------|------|---------|
| H1 ci_gate 探测 | S1 | S2-S7 | ✅ 持续（Sprint 7 gate 含 ebpf_lint） |
| H3 脚本化 | S1 | S2-S7 | ✅ 持续（tmp/sprint7-*.sh 全程） |
| H4 关联文件 | S1 | S2-S7 | ✅ 持续（T1/T2 同 scripts/ 目录关联） |
| H5 bench+memprofile | S2 | S3-S7 | N/A（harness Sprint 无 bench） |
| H6 fidelity 语言无关 | S3 | S4-S7 | ✅ .sh 文件按扩展名追踪 |
| H7 CPU profile | S4 | S4-S7 | N/A（非 CPU 主题） |
| H8 bench harness deadline | S4 | S5-S7 | N/A |
| H9 target_files 重叠检测 | S4 | S5-S7 | ✅ T1/T2 独立文件域，0 重叠 → parallel |
| **H10 deletion_protection 增强** | **S5 proposed** | **S7 首次** | ✅ **首次应用**（T1 脚本，ISSUE-1 案例红绿双通过） |
| H11 CRLF 检查 | S6 proposed | — | deferred（Sprint 7 未触发 CRLF 污染） |
| **H12 fork 验证 harness** | **S6 proposed** | **S7 首次** | ✅ **首次应用，价值实证**（T2 捕获 fork quic-go 4 处失败） |

### H10 生效证据（首次应用）

- **Sprint 5（H10 前）**：ISSUE-1 触发 —— 误删 bpf_bug_verification_test.go 导致 ci_gate_ebpf_test 回归，L2 retry 修复（成本：1 commit + Dev/QA 周期）
- **Sprint 7（H10 后）**：T1 脚本对 ISSUE-1 同案例正确报 4 hits（Makefile:136/151/166/181 的 `go generate`）+ exit 1。**未来涉及删除的 Sprint 跑 T1 即可避免同类回归**
- **EDGE 验证**：tproxy.c → 2 hits（Makefile EBPF_LINT_SOURCES + ebpf-audit.sh:59），正确识别非删目标

### H12 生效证据（首次应用，价值实证）

- **Sprint 6（H12 前）**：fork 验证 gap 是"假设"（OQ-S6-3 用户关切，但无证据 fork 真有 bug）
- **Sprint 7（H12 后）**：T2 实跑发现 fork quic-go @ dff8aaa5 在自己测试套件中有 4 处失败，含 1 个 panic。**fork bug 从"假设"变为"已证实"**
- **advisory 价值**：不阻塞 dae Sprint，但产出可读报告供 Producer 评估 + fork 维护者修复
- **--strict 价值**：未来 fork bump 决策时用 --strict，可防止引入新 bug

## 矿脉评估：harness 矿脉是"基础设施投资"，产出密度低但长期杠杆高

| Sprint | 矿脉 | 矿脉类型 | 产出密度 |
|--------|------|----------|---------|
| S1-S3 | Go alloc perf | 收割型（短期） | 高（每次直接 allocs/op 下降） |
| S4 | lifecycle 重构 | 收割型 | 高 |
| S5 | tech-debt cleanup | 收割型 | 中（含测试瘦身 + CPU 算法） |
| S6 | stability verification | 验证型（0 代码） | 极低（产出是信心） |
| **S7** | **harness completion** | **基建型（长期杠杆）** | **低（2 个脚本，但每次未来 Sprint 受益）** |

**洞察**：harness 矿脉与收割型矿脉本质不同 —— 不产出即时性能/稳定性提升，但**降低未来 Sprint 的失败概率**。Sprint 5 ISSUE-1 已实证"无 H10 的成本"（1 L2 retry commit + Dev/QA 周期）。H10 应用后此类成本归零。

## Sprint+1 候选

| 候选 | 来源 | 性质 | ROI |
|------|------|------|-----|
| 巨型文件拆分（control_plane.go 4005 等） | S5+S7 重复识别 | 架构重构 | 中高（长期杠杆，条件已成熟） |
| fork quic-go 测试失败修复 | S7 OQ-S7-1 | fork 维护 | 中（外部工作，跨仓库） |
| eBPF tproxy.c 精简 | S5 候选 | 内核态 perf | 中低（需 clang IR 前置） |

**推荐 Sprint 8**：巨型文件拆分（control_plane.go 4005 + control_plane_core.go 1311 同簇 5316 行）。Sprint 6 已对 dns_control/udp_endpoint_pool/run.go 做拆分验证 0 回归，模式可复用。需新 Sprint 类型 `architecture_refactor_allowed`。

## Harness backlog 更新

- **H10** ✅ applied（Sprint 7 首次）：deletion_protection 扫 Makefile/CI/scripts
- **H11** 🟡 pending（Sprint 6 proposed）：Dev WSL 操作后 CRLF 检查（本 Sprint 未触发）
- **H12** ✅ applied（Sprint 7 首次）：fork 跨仓库验证（advisory 默认 + strict fork bump 决策）

## 跨 Sprint 复利总结（7 Sprint 数据点）

| 维度 | 演进 |
|------|------|
| no-op 率 | 57% → 33% → 0% → 0% → 0% → 0% → **0%**（连续 4 Sprint 零 no-op） |
| harness 改进 | 0 → H1-H4 → H1-H5 → H1-H8 → H1-H10 → H1-H12 → **H1-H12 (10 applied)** |
| 方法论维度 | grep → bench → bench+mem → +CPU → +tech-debt → +stability → **+harness 完备化** |
| 约束/矿脉 | semantic → lifecycle → tech-debt → stability → **harness** |
| lessons | L1-L8 → L1-L17 → L1-L20 → **L1-L21**（+L21 fork deps GOPROXY） |
| Sprint 类型 | perf×3 → lifecycle → tech-debt → stability → **harness**（5 类） |

**Sprint 7 复利实证**：
1. **H10/H12 双 harness 应用** = Sprint 5/Sprint 6 投资的 pending 项首次兑现。证明"proposed → applied"链路有效
2. **T2 价值从假设到实证** = H12 不是防御性假设，是真实存在的 fork gap。fork quic-go @ dff8aaa5 有 panic
3. **CEO 直接编排** = 轻量路径对 scope 小 + 决策明确的 Sprint 有效，不必每次都走完整团队编排
4. **连续 4 Sprint 零 no-op**（S4-S7）：跨 4 类矿脉（lifecycle/tech-debt/stability/harness）持续，证明方法论已成熟到矿脉+约束类型无关

**待检验假设**：Sprint 7 是首次"基建型"Sprint，产出密度低（2 脚本）。**长期 ROI 取决于未来 Sprint 实际调用 T1/T2 的频次**。如果 Sprint 8+ 频繁触发 deletion_protection（删文件 Sprint）或 fork bump，H10/H12 投资回本；否则低 ROI。下次涉及删除/fork bump 的 Sprint 须记录是否调用 T1/T2。
