# Sprint 8 Hill Climbing Report

> 生成：2026-08-05（dev 完成后，主对话三通道验证 + QA 自验后 CEO L4 自执行）
> Sprint 主题：架构重构（**新 Sprint 类型** architecture_refactor_allowed）
> **里程碑**：首次架构重构 Sprint + 首次 CEO 委派 kixpower-dev 做大文件拆分 + 三通道语义验证首次系统化应用（函数集合 / body diff / numstat 三维交叉）+ 0 回归 0 新 lesson（拆分顺利）

## Trace 聚合（8 Sprint 对比）

| 指标 | S1 | S2 | S3 | S4 | S5 | S6 | S7 | **S8** | 趋势 |
|------|----|----|----|----|----|----|----|--------|------|
| trace_count | 7 | 3 | 1 | ~11 | ~8 | ~15 | ~10 | ~6 | 架构重构，trace 少（机械操作） |
| silent_failures | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** | 持平（优） |
| goal_drifts | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** | 持平（优） |
| l2_failures | 0 | 0 | 0 | 0 | 1 | 0 | 0 | **0** | 持平 |
| over_budget | 0 (4/5) | 0 (2/2) | 0 (1/2) | 0 (3/4) | 0 (4/5) | 0 (1/3) | 0 (2/3) | **0 (TBD)** | 持平 |
| no_op_tasks | 57% | 33% | 0% | 0% | 0% | 0% | 0% | **0%** | 持平（连续 5 Sprint） |
| topology | serial | serial | serial | hybrid→seq | seq | seq | parallel | **sequential (T1 内部)** | 单 task 内部顺序 |
| commits_used | 4/5 | 2/2 | 1/2 | 3/4 | 4/5 | 1/3 | 2/3 | **TBD** | — |
| Sprint 类型 | perf | perf | perf | lifecycle | tech-debt | stability | harness | **architecture_refactor** | 首次架构重构 |

## 新模式识别（Sprint 8 特有）

### 1. 三通道语义验证首次系统化应用

Sprint 1-7 的验证主要靠 gate（vet/build/test/race）+ bench（perf Sprint）。Sprint 8 是**架构重构**，gate 通过只能证明"能编译能跑"，**不能证明"语义不变"**。

为补足，首次系统化应用三通道语义验证：
- **Channel 1（函数集合）**：原文件 vs 新文件合并，顶层 func 集合 diff（136=136）
- **Channel 2（body diff）**：原文件 vs 新文件合并，sorted unique 非空行 diff（76 行差异全是 license/package/import 重复）
- **Channel 3（numstat）**：control_plane.go diff 是 `0 add / 981 del`（纯删除）

三通道一致 → 高置信"0 逻辑改动"。**比单靠 gate 强得多**（gate 不区分"语义不变的拆分"与"改了逻辑但恰好编译通过"）。

**实证**：这是 kixparadigm 三通道交叉验证在架构重构场景的有效性证明。dev 自报告"0 逻辑改动"被独立验证为真。

### 2. dev 子代理对大文件拆分的可靠性

Sprint 8 委派 kixpower-dev 做 4315 行文件的拆分。dev 策略：
- **最小簇先验证工具链**（parse 68 行手动）
- **大簇用 Python 脚本批量提取**（按 `^func` + `^}` 边界，避免转录错误）
- **import 自动分析 + go build 校验**

**关键**：dev 发现了我 prompt 的 typo（`SharesActiveDnsController` → `...With`），实际读代码纠错。**dev 子代理不盲目执行 prompt**。这是 AI 子代理可靠性的强信号 —— prompt 不需要 100% 精确，dev 会读代码自校正。

### 3. 架构重构矿脉验证（Sprint 5/7 识别的候选）

| Sprint | 巨型文件识别 | 决断 |
|--------|-------------|------|
| S5 hill-climbing | control_plane.go 4040 等 → "中高 ROI，条件已成熟" | deferred |
| S7 hill-climbing | "推荐 Sprint 8 = 巨型文件拆分" | 启动 |
| **S8** | **control_plane.go 4315 → 3334（-23%），0 回归** | **验证有效** |

**矿脉评估**：架构重构矿脉**有效但 scope 控制**重要。Sprint 8 只拆 1 个文件（control_plane.go），不碰 control_plane_core.go（1311）/ dns.go（1273）/ udp.go（1172）—— 留 Sprint 9+。单 Sprint 单文件降低风险。

### 4. PowerShell `$?` 陷阱对外部 agent 也有效（L7 复利）

dev 子代理在验证时遇到 PowerShell `$?` 被自身解析（返回 True/False）。dev 自己学到改用脚本文件（tmp/sprint8-*.sh）。

**复利实证**：L7 是 Sprint 1 lesson（PowerShell 调 wsl 转义陷阱），固化在 H3（脚本化）。Sprint 8 dev 子代理独立"重新发现"这个 lesson —— **说明 L7/H3 不是过度规则**，是真实反复出现的 failure mode。外部 agent（dev）也会踩，证明 lesson 的普适性。

## H1-H12 Eval 对照（8 Sprint）

| 改进项 | 应用 | S8 验证 |
|--------|------|---------|
| H1 ci_gate 探测 | S2-S8 | ✅ make ebpf-test 23 用例全过 |
| H3 脚本化 | S2-S8 | ✅ tmp/sprint8-*.sh 全程（dev 也独立学到） |
| H4 关联文件 | S2-S8 | ✅ T1 target_files 含 control_plane_* 同簇 |
| H5 bench+memprofile | S3-S8 | N/A（非 perf 主题） |
| H6 fidelity 语言无关 | S4-S8 | ✅ .go 文件按扩展名追踪 |
| H7 CPU profile | S4-S8 | N/A |
| H8 bench harness deadline | S5-S8 | N/A |
| H9 target_files 重叠检测 | S5-S8 | ✅ 单文件拆分，无重叠 |
| H10 deletion_protection 增强 | S7-S8 | ✅ 持续（Sprint 8 不涉删除，但脚本可用） |
| H11 CRLF 检查 | pending | deferred（Sprint 8 未触发 CRLF 污染） |
| H12 fork 验证 harness | S7-S8 | ✅ 持续（Sprint 8 不涉 fork bump） |

**新候选**：无。Sprint 8 拆分顺利，无新 failure mode 暴露。

## 矿脉评估：架构重构矿脉仍丰饶

Sprint 8 拆 1 个文件（control_plane.go），剩余巨型文件：

| 文件 | 行数 | 性质 | Sprint 9 候选？ |
|------|------|------|----------------|
| control/kern/tproxy.c | 2886 | eBPF（需 clang IR） | 否（不同矿脉） |
| control/kern/tests/bpf_test.c | 1923 | eBPF 测试 | 否 |
| control/control_plane_core.go | 1311 | bpf hook + 接口绑定 + routing | **是**（同模式可拆） |
| control/dns.go | 1273 | DNS 处理 | **是**（需先看结构） |
| component/outbound/dialer/connectivity_check.go | 1153 | dialer | 中（独立模块） |
| control/dns_controller_cache.go | 1151 | DNS cache | **是**（同模式可拆） |

**推荐 Sprint 9**：control_plane_core.go（1311 → 3 簇：bpf hook lifecycle + 接口绑定 + domain routing/udp conn state）。同 Sprint 8 模式可复用，scope 相当（~1300 行 vs Sprint 8 的 981 行提取）。

## 跨 Sprint 复利总结（8 Sprint 数据点）

| 维度 | 演进 |
|------|------|
| no-op 率 | 57% → 33% → 0% → 0% → 0% → 0% → 0% → **0%**（连续 5 Sprint 零 no-op） |
| harness 改进 | 0 → H1-H4 → H1-H5 → H1-H8 → H1-H10 → H1-H12 → H1-H12（10 applied） → **H1-H12（持续）** |
| 方法论维度 | grep → bench → +mem → +CPU → +tech-debt → +stability → +harness → **+三通道语义验证（架构重构场景）** |
| Sprint 类型 | perf×3 → lifecycle → tech-debt → stability → harness → **architecture_refactor**（6 类） |
| lessons | L1-L8 → L1-L17 → L1-L21 → **L1-L21（无新 hard lesson）** | — |

**Sprint 8 复利实证**：
1. **三通道语义验证**：首次系统化用于架构重构场景。gate 通过 ≠ 语义不变；三通道（函数集合 / body diff / numstat）补足语义维度。**比单靠 gate 强得多**
2. **dev 子代理可靠性 > prompt 准确性**：dev 发现并纠正 prompt typo。prompt 不需要 100% 精确
3. **架构重构矿脉验证**：Sprint 5/7 识别 → Sprint 8 兑现，0 回归。矿脉评估有效
4. **连续 5 Sprint 零 no-op**（S4-S8）：跨 5 类矿脉（lifecycle/tech-debt/stability/harness/architecture）持续

## Sprint+1 候选

| 候选 | 来源 | ROI |
|------|------|-----|
| control_plane_core.go 拆分（1311 → 3 簇） | S8 OQ-S8-1 | 高（同模式，scope 相当） |
| dns.go / dns_controller_cache.go 拆分 | S8 OQ-S8-2 | 中（需先看结构） |
| eBPF tproxy.c 精简 | S5 候选 | 中低（需 clang IR 前置） |
| dev Python 脚本沉淀为通用拆分工具 | S8 OQ-S8-3 | 低（若 Sprint 9 继续拆分再做） |
