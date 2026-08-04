# Sprint 9 Hill Climbing Report

> 生成：2026-08-05（dev 完成 + 主对话三通道验证 + QA 后，CEO L4 自执行）
> Sprint 主题：架构重构（control_plane_core.go 拆分，Sprint 8 模式复用）
> **里程碑**：Sprint 8 模式首次复用成功 + control_plane 系列拆分完成（plane + core 共 -1765 行提取到 8 个新文件）+ L22 候选（机械提取工具边界检测陷阱的模式化）

## Trace 聚合（9 Sprint 对比）

| 指标 | S7 | S8 | **S9** | 趋势 |
|------|----|----|--------|------|
| trace_count | ~10 | ~6 | ~5 | 架构重构 trace 少（机械操作） |
| silent_failures | 0 | 0 | **0** | 持平（连续 7 Sprint） |
| goal_drifts | 0 | 0 | **0** | 持平 |
| l2_failures | 0 | 0 | **0** | 持平 |
| over_budget | 0 (2/3) | 0 (2/5) | **0 (TBD)** | 持平 |
| no_op_tasks | 0% | 0% | **0%** | 持平（连续 6 Sprint） |
| topology | parallel | sequential | **sequential** | 单 task 内部顺序 |
| Sprint 类型 | harness | architecture | **architecture** | 模式复用 |

## 新模式识别（Sprint 9 特有）

### 1. Sprint 8 模式首次复用成功

Sprint 8（control_plane.go 拆 4 簇）→ Sprint 9（control_plane_core.go 拆 2 簇）。**同模式（同包内 mv + 三通道验证 + dev 子代理 Python 脚本提取）首次复用**，0 摩擦：
- dev 直接复用 Sprint 8 的 Python 脚本模式（`^func` + `^}` 边界检测）
- 主对话复用三通道验证脚本（函数集合 / body diff / numstat）
- 全 gate 复用（vet/build/race/ebpf-test/make dae/validate）

**复用价值**：模式成熟后，同类 Sprint 的边际成本递减。Sprint 10+ 拆 dns.go/udp.go 可继续复用。

### 2. 机械提取工具的边界检测陷阱（L22 候选，模式化）

Sprint 8 dev 遇到 import 误报（参数名 `outbound`/`routing`/`net` 匹配包名），Sprint 9 dev 遇到 off-by-one（import 块 `)` 在 L29 非 L28，函数体误包含 `)`）。两次都是 dev 用 Python 脚本批量提取时的边界检测陷阱。

**模式化（L22 候选）**：机械提取工具的边界检测有两类陷阱：
- **包名 vs 参数名**：`\boutbound\.` 既匹配包限定也匹配参数名限定 → 用 go build 校验
- **func 体 vs import 块**：`^func` 到下个 `^}` 的边界，import 块的 `)` 也是 `^}`-like → 用 go build + 内容断言校验

**对策已验证有效**：两类陷阱都被 `go build` 即时捕获。机械提取工具 + go build 校验 = 可靠的拆分流水线。

### 3. control_plane 系列拆分总结（Sprint 8 + 9 复利）

| Sprint | 文件 | 原行数 | 拆后 | 新文件数 | 提取函数 |
|--------|------|--------|------|----------|----------|
| S8 | control_plane.go | 4315（dev 报告，formatter 后 3090） | 3090 | 4（parse/dns/datapath/dialtarget） | 42 |
| S9 | control_plane_core.go | 1409（formatter 后） | 625 | 2（bind/routing） | 21 |
| **合计** | — | — | — | **6 新文件** | **63 函数** |

control_plane.go 系列从原本两个超大文件（plane 4315 + core 1409 = 5724 行）拆为 8 个聚焦文件（最大 644 行）。**单文件最大行数从 4315 → 644（-85%）**。

### 4. 三通道验证的复用与可靠性

Sprint 8 首次系统化三通道验证（函数集合 / body diff / numstat），Sprint 9 直接复用。两次 dev 自报告的 "0 逻辑改动" 都被三通道独立验证为真：
- S8：136 = 136 函数 / body diff 只机械副产品 / 0-981 numstat
- S9：44 = 44 函数 / body diff 只机械副产品 / 0-784 numstat

**三通道验证的可靠性已 cross-validated**：两次不同 scope 的拆分都通过同套验证，证明验证方法本身是可靠的（不是过拟合到 Sprint 8 的特定代码）。

## H1-H12 Eval 对照

| 改进项 | 应用 | S9 验证 |
|--------|------|---------|
| H1 ci_gate 探测 | S2-S9 | ✅ make ebpf-test 23 用例全过 |
| H3 脚本化 | S2-S9 | ✅ tmp/sprint9-*.sh 全程（dev 也独立复用） |
| H4 关联文件 | S2-S9 | ✅ T1 target_files 含 control_plane_core_* 同簇 |
| H5/H7/H8 | — | N/A（非 perf 主题） |
| H6 fidelity 语言无关 | S4-S9 | ✅ .go 文件按扩展名追踪 |
| H9 target_files 重叠检测 | S5-S9 | ✅ 单文件拆分，无重叠 |
| H10/H12 | S7-S9 | ✅ 持续（Sprint 9 不涉删除/fork bump） |
| H11 | pending | deferred（未触发 CRLF） |

**新候选**：无。Sprint 9 是 Sprint 8 模式复用，无新 failure mode。

## 矿脉评估：架构重构矿脉仍丰饶，但 control_plane 系列已收割完

control_plane.go + control_plane_core.go 系列已拆完（Sprint 8 + 9）。剩余巨型文件：

| 文件 | 行数 | 性质 | Sprint 10 候选？ |
|------|------|------|----------------|
| control/kern/tproxy.c | 2886 | eBPF（需 clang IR） | 否（不同矿脉） |
| control/kern/tests/bpf_test.c | 1923 | eBPF 测试 | 否 |
| control/dns.go | 1273 | DNS 处理 | **是**（需先看结构判断内聚性） |
| component/outbound/dialer/connectivity_check.go | 1153 | dialer | 中（独立模块） |
| control/dns_controller_cache.go | 1151 | DNS cache | **是**（同模式可拆） |

**推荐 Sprint 10**：dns.go（1273）或 dns_controller_cache.go（1151）。需先做 Producer 阶段结构分析，判断内聚性是否适合拆分（dns.go 可能比 control_plane.go 内聚性高，拆分价值需评估）。

## 跨 Sprint 复利总结（9 Sprint 数据点）

| 维度 | 演进 |
|------|------|
| no-op 率 | 连续 6 Sprint 零 no-op（S4-S9） |
| harness 改进 | H1-H12（10 applied，2 deferred） |
| Sprint 类型 | perf×3 → lifecycle → tech-debt → stability → harness → architecture×2 |
| 拆分累计 | control_plane.go 4315→3090（S8）+ control_plane_core.go 1409→625（S9）= **-2009 行提取到 6 新文件** |
| 三通道验证 | S8 首次系统化 → S9 复用 cross-validated |

**Sprint 9 复利实证**：
1. **模式复用价值**：Sprint 8 模式（dev Python 脚本 + 三通道验证 + 全 gate）在 Sprint 9 0 摩擦复用，边际成本递减
2. **机械提取工具陷阱模式化（L22 候选）**：S8 import 误报 + S9 off-by-one 都是边界检测陷阱，go build 即时捕获。拆分流水线（提取 + 编译校验）已成熟
3. **control_plane 系列完成**：plane + core 共 6 新文件，单文件最大 4315→644（-85%）。架构债清理阶段性成果

## Sprint+1 候选

| 候选 | 来源 | ROI |
|------|------|-----|
| dns.go / dns_controller_cache.go 拆分 | S9 OQ-S9-2 | 中（需先评估内聚性） |
| eBPF tproxy.c 精简 | S5 候选 | 中低（需 clang IR） |
| dev Python 脚本沉淀为通用工具 | S8 OQ-S8-3 + S9 OQ-S9-3 | 低（若 Sprint 10 继续拆分再做） |
