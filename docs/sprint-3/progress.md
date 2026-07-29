---
sprint: 3
sprint_theme: "Memory optimization via H5 (bench + memprofile dual verification)"
phase: dev-complete
owner: Remy
branch: kdae
created: 2026-07-29

# === blast_radius（plan 锁定）===
blast_radius:
  commit_budget: 2
  commit_budget_formula: ceil(task_count/3) + strong_coupling_count + 1
  hard_cap: 10
  commits_used: 1
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true

# === topology ===
topology_used: serial
topology_rationale: "T1 单 task，无并行"

# === task DAG 摘要 ===
tasks:
  T1: {status: done, files: [control/udp_endpoint_pool.go], source: "H5 bench+memprofile", bench: "UdpProxyDial/cache=miss=18 allocs/op (前后持平，符合预期)", expected: effective_small, h5_verdict: "PROD; bulk inherent, residual=errStrLower (已消除)", memprofile_evidence: "strings.ToLower cum 32768 allocs (1.19%) → 0 (从 top 50 消失)"}

# === Dev L2 verification（mode 要求字段）===
completed_tasks: 1
artifacts_changed_since_last_observe:
  - control/udp_endpoint_pool.go   # T1: errStrLower → containsFoldASCII
  - tmp/sprint3-gates.sh            # H3 gate 脚本
  - tmp/sprint3-baseline.sh         # H3 before-memprofile 脚本
  - docs/sprint-3/progress.md       # 本文件
l2_verification_passed: true        # vet/build/test/race/bench/memprofile 全过

# === verifiable_gates 状态 ===
gates:
  go_vet: pass         # EXIT=0
  go_build: pass       # EXIT=0
  go_test: pass        # control 25.5s + component 全 ok
  go_test_race: pass   # control 28.0s
  benchmark_no_regression: pass   # 18 allocs/op 前后持平（errStrLower 在错误路径，bench noise 主导；memprofile_review 为决定性证据）
  memprofile_review: pass         # H5 决定性：strings.ToLower cum 32768→0，errStrLower/MakeNoZero(genSplit) 全消失
  ci_gate_ebpf_test: pass       # QA 实跑 8/8 PASS（3.224s，H1 持续；T1 无 .c 改动，回归安全）
  ci_gate_make_da_ebpf: pass      # EXIT=0（F1）
  ebpf_lint: na
  ebpf_sync_check: pass         # QA 实跑 EXIT=0（无 C 结构体改动）
---

# Sprint 3 Progress — 基于 H5 的内存优化（bench+memprofile 双验证）

> 执行期由 Dev/QA 填写。阶段过渡时 Remy 更新本文件与 PROJECT_BRIEF.md 第 7、8 节。

## 状态总览 / Status

| 阶段 | 负责人 | 状态 |
|------|--------|------|
| Planning（drift-check + H5 memprofile 分类 + plan） | Remy | ✅ 完成 |
| Dev 实现（T1 errStrLower + bulk inherent 文档化） | Dev | ✅ 完成 |
| QA 验证（gate 全过 + memprofile 复核） | QA | ✅ 完成（PASS，见 docs/qa/qa-signoff-3.md） |

## Trace Log

<!-- 每次任务推进追加一行：[时间] task | 动作 | 结果 | commit? -->

- [2026-07-29] planning | drift-check 完成（4 项：context 零漂移 / L1-L9 全规避 L9 成核心 / 无新 OQ sniffing 候选经 memprofile 复核仍超边界 / fidelity 100% gated 但脚本假阴性→H6）；Evals：H1/H2/H3 全通过，H5 新项首次应用 | drift-check.md | —
- [2026-07-29] H5 扫描 | Phase1 全量 bench 调研（tmp/sprint3-survey.sh，-benchtime=300ms，SURVEY_EXIT=0）；Phase2 逐包 memprofile（tmp/sprint3-mem2.sh，F3：-memprofile 不可跨包）；4 候选分类：D=WriteToBufferFlush 95.73% harness（net.IPv4 76.58%+listen 19.15%）→过滤；B=QUIC 59% crypto+Sprint2-exhausted→排除；C=SniffTcp lifecycle-boundary→排除；A=UdpProxyDial PROD bulk inherent residual=errStrLower→T1 | runtime-context.md §H5 | —
- [2026-07-29] planning | H6 发现并记录：verification-fidelity-check.ps1 假设 src/ 布局，Go 项目假阴性 PASS（PASS no_source_changes）；手动 git-log 为权威 | drift-check.md §4 frontmatter + backlog H6 | —
- [2026-07-29] planning | task_sizing：task_count=1, strong_coupling=0 → commit_budget=⌈1/3⌉+0+1=2（hard_cap=10）；thin Sprint 是 H5 应用于已优化 2 Sprint 代码库的正确预期 | plan.md blast_radius | —
- [2026-07-29] T1 实现 | 用零分配 `containsFoldASCII`（ASCII 路径 inline A-Z 折叠；遇非 ASCII 字节回退 `strings.Contains(strings.ToLower(s), substr)` 保证 Unicode 完全等价）替换 `errStrLower`（`strings.ToLower(err.Error())`）；删除 `errStrLower` 函数，3 个 Contains 调用点改为 containsFoldASCII | control/udp_endpoint_pool.go | 待提交
- [2026-07-29] T1 gate | 全套 gate 通过（F1 make ebpf=0 / vet=0 / build=0 / test control+component ok / race control ok / bench UdpProxyDial PASS）；脚本 tmp/sprint3-gates.sh | — | —
- [2026-07-29] T1 H5 决定性验证 | before/after memprofile 严格对照（git stash 临时回退源文件跑 baseline）：**before** strings.ToLower cum=32768 allocs(1.19%)+errStrLower cum=32768+MakeNoZero flat=32768；**after** 三者全部从 top 50 消失 → ToLower 路径 32k 对象分配**完全消除**。bench allocs/op 18→18 持平（errStrLower 在错误路径，bench 高方差：无关函数 registerEndpoint/func1/closeQuicBenchmarkEndpoint 运行间也波动 30-50%，证实 bench 非确定性 read-loop 迭代主导噪声）| tmp/sprint3-baseline.sh + 本文件 §H5 对比表 | —
- [2026-07-29] T1 bulk inherent 文档化 | context.WithDeadlineCause / registerEndpoint / time.NewTimer / createEndpointLocked + err.Error() 五项记为 inherent no-op（OQ-S3-2 闭环），见本文件 §Bulk inherent | — | —

## Benchmark 基线（Dev 改动前对照，来自 runtime-context.md §H5）

| Benchmark | 基线 allocs/op | 改动后 | Δ | 任务 | 备注 |
|-----------|---------------|--------|---|------|------|
| BenchmarkUdpProxyDial/cache=miss | 18 (5230 B/op) | 18 (5238 B/op) | 持平（ΔB=+8 噪声） | T1 | errStrLower 在错误路径，bench 高方差；memprofile_review 为决定性证据（见 §H5 对比） |
| BenchmarkWriteToBufferFlush | 60 | — | — | （过滤） | H5：95.73% harness，不设 task |

## H5 memprofile 决定性对比（T1 核心验证）

**方法**：`git stash push control/udp_endpoint_pool.go` 临时回退源文件跑 baseline memprofile，再 `git stash pop` 恢复，跑 after memprofile。脚本：tmp/sprint3-baseline.sh + tmp/sprint3-gates.sh。

| 函数 | before flat | before cum | after flat | after cum | 结论 |
|------|------------|------------|------------|-----------|------|
| `strings.ToLower` | 0%（被 inline） | **32768 (1.19%)** | — | — | **消除**（从 top 50 消失）✅ |
| `control.errStrLower` | 0%（被 inline） | **32768 (1.19%)** | — | — | **消除**（函数已删）✅ |
| `internal/bytealg.MakeNoZero` | **32768 (1.19%)** | 32768 | — | — | **消除**（ToLower 路径的 byte alloc）✅ |
| `strings.genSplit` | 32768 (1.19%) | 32768 | — | — | **消除**（ToLower 路径）✅ |
| `(*UdpEndpoint).isConnectionRefused` flat | 196609 (7.11%) | 229377 (8.30%) | 393218 (13.90%) | 393218 (13.90%) | flat% 波动 = bench 高方差噪声（err.Error() alloc 仍在 = inherent，见 §Bulk）；非 ToLower 回归 |

**关键证据**：ToLower 路径的 32768 对象分配（cum 1.19%）在 after 完全消失，证实 `errStrLower` 的 strings.ToLower alloc 已被 `containsFoldASCII` 零分配路径消除。isConnectionRefused flat% 数字波动（7%→14%）系 bench 非确定性 read-loop 迭代次数主导（无关函数 registerEndpoint 9%→13.5%、closeQuicBenchmarkEndpoint 11%→7.6% 同期同向波动佐证），**非 ToLower 回归**——ToLower/errStrLower/MakeNoZero 三者在 after profile 中均不存在。

**语义等价论证**（plan safety_condition 兑现）：`containsFoldASCII` 对所有输入 byte-for-byte 等价于 `strings.Contains(strings.ToLower(s), substr)`：
1. **纯 ASCII s**：inline 'A'-'Z' 折叠与 `strings.ToLower` 的 ASCII 处理逐字节一致；
2. **s 含任意非 ASCII 字节（≥0x80）**：函数回退到原 `strings.Contains(strings.ToLower(s), substr)` 路径，保留完整 Unicode 正确性（规避 U+212A KELVIN SIGN→'k' 等罕见 Unicode 大小写折叠差异）。代理/系统调用错误消息实际为 ASCII，回退分支生产中永不命中，但保证零行为差异。

## H5 应用证据（供 done.md / hill-climbing）

| 维度 | Sprint 2（H5 前） | Sprint 3（H5 应用后） |
|------|-------------------|----------------------|
| harness-noise task 在 Producer 阶段过滤数 | 0（T2 在 Dev 阶段才发现） | 1（WriteToBufferFlush 60 allocs/3.6MB 在 Producer 阶段即过滤） |
| 设 task 数 | 3（T1/T2/T3） | 1（T1） |
| 预期 no-op 率 | 33%（1/3，T2） | T1 expected effective_small（errStrLower 真实消除）；bulk inherent 部分文档化非 task |

## Gate 执行记录

| Gate | 命令 | 结果 | 备注 |
|------|------|------|------|
| F1 make ebpf | `make ebpf` | EXIT=0 | 生成 bpf 绑定（H5 扫描已验证） |
| go_vet | `go vet -tags=$BT ./...` | EXIT=0 | — |
| go_build | `go build -tags=$BT ./...` | EXIT=0 | — |
| go_test | `go test -tags=$BT ./control/... ./component/...` | PASS | control 25.5s + component 全 ok |
| go_test_race | `go test -tags=$BT -race ./control/...` | PASS | control 28.0s |
| benchmark_no_regression | `go test -bench=UdpProxyDial -benchmem -benchtime=300ms` | PASS | 18 allocs/op 前后持平（符合预期） |
| memprofile_review（H5 决定性） | `go test -bench -memprofile + pprof -top -sample_index=alloc_objects` | PASS | strings.ToLower cum 32768→0；详见 §H5 对比表 |
| ci_gate_make_da_ebpf | `make ebpf` | EXIT=0 | 同 F1 |
| ci_gate_ebpf_test | `make ebpf-test` | ✅ PASS（QA 实跑 3.224s，8/8） | H1 持续；T1 无 .c 改动，回归安全 |
| ebpf_sync_check | `make ebpf-sync-check` | ✅ PASS（QA 实跑 EXIT=0） | progress 标 pending 由 QA 闭环 |

## Bulk inherent no-op 文档化（OQ-S3-2 闭环）

> H5 要求 harness/inherent 判定有据可查，避免被误读为 silent no-op。以下 5 项为 memprofile 中 isConnectionRefused 之外的生产分配热点，经论证为 inherent（消除即破坏语义），Dev 不改、仅文档化。

| 函数 | memprofile flat%（before/after） | inherent 论证（1 句） |
|------|----------------------------------|----------------------|
| `context.WithDeadlineCause` | 12.11% / 10.17% | 拨号超时上下文机制（首次拨号 + retry 共 2 处）；消除即失去超时语义，UDP 拨号会无限等待死代理。 |
| `(*UdpEndpointPool).registerEndpoint` | 9.10% / 13.52% | map 插入新 endpoint 到 dialerIndex bucket；新 endpoint 必须被索引才能被后续 GetOrCreate 查找复用，否则池化失效。 |
| `time.NewTimer` (+ newTimer) | 8.24%+3.39% / 6.84%+6.12% | 随 `context.WithTimeout`（context 包内部用 timer 实现超时）；与 WithDeadlineCause 同源，无法独立消除。 |
| `(*UdpEndpointPool).createEndpointLocked` | 11.75%(cum) / 6.62%(cum) | `&UdpEndpoint{}` 结构体本身 + `newDataSessionLifecycleProfile`；endpoint 对象必须分配才能存在，是池化的载体而非池化目标。 |
| `err.Error()`（在 isConnectionRefused flat 内） | isConnectionRefused flat 7.11%→13.90% | err 类型的 Error() 方法构建消息时分配（如 *net.OpError 拼接字段）；属错误对象自身契约，改它即改错误类型，超 T1 范围。 |

**合计**：上述 5 项 = 拨号超时机制（context+timer）+ endpoint 对象生命周期（struct+map 索引）+ 错误消息构建，均为语义不可消除的内禀分配。T1 仅消除其上的 residual（errStrLower 的 ToLower 冗余拷贝），不改这些 inherent 项。

## Evals 回归结果（v4.1，供 done.md）

| ID | eval.regression_signal | Sprint 2 命中？ | Sprint 3 处置 | 结果 |
|----|------------------------|----------------|--------------|------|
| H1 | ci_gate.*ignored | ❌ | 延续 runs | eval 通过 ✅ |
| H2 | no_op_tasks.*[4-9]/ | ❌（1/3） | bench 驱动 + H5 过滤 | eval 通过 ✅ |
| H3 | EXIT_(BUILD\|TEST)=True | ❌ | 脚本化 | eval 通过 ✅ |
| H5 | harness.*allocs.*flat=0 | —（新项） | Producer 阶段 memprofile 分类 | 待 QA 终验（T1 memprofile_review） |

## 开放问题追踪

- OQ-S3-1：errStrLower 在 bench 是否真实触发 refused。**已闭环** ✅：memprofile 证实 isConnectionRefused 在 bench 中被调用（before cum 229377 / after cum 393218 allocs，~3-5 次/op），strings.ToLower 路径 32768 allocs 真实存在且改后消失。bench allocs/op 数字 18→18 持平系高方差噪声主导（非路径未触发）。
- OQ-S3-2：bulk inherent 文档化。**已闭环** ✅：见 §Bulk inherent no-op 文档化（context/timer/struct/map/err.Error 五项，各附 1 句 inherent 论证）。

## Sprint+1 候选（L4 Hill Climbing 输入，Sprint 结束时由 QA 填）

- （预期）sniffing lifecycle 重构（NewStreamSniffer/async-read/StreamSniffer 池化）—— Sprint 1/2/3 三次确认为超语义等价边界，跨 3 Sprint 数据点强信号，建议 Sprint+1 改主题为"lifecycle refactor"（非 semantic-preserving）。
