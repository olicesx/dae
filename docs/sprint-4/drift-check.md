---
sprint: 4
check_type: cross-sprint-drift
run_by: Remy
run_at: 2026-07-29
prev_sprint: 3
sprint_theme: "Sniffing lifecycle refactor + CPU profile methodology (H7)"
constraint_policy: lifecycle_refactor_allowed
verification_fidelity_method: authoritative-git-log
verification_fidelity_h6_applied: true
verification_fidelity_script_note: >
  H6 应用：verification-fidelity-check.ps1 已含 Get-ModulePrefixes 动态目录发现（src/ 假设已修，
  不再返回假阴性 PASS no_source_changes）。本次实跑确认能检测到 .go 源码改动。
  残留问题：-SinceDate 默认 30 天窗口过宽，把 Sprint 1/2 的源码 commit 也扫入，导致 43.1% ungated 假象。
  权威方法仍为 git-log 按 Sprint 边界 commit range（见 §4）。H6 在 backlog 标 ✅ applied（动态目录发现生效）。
---

# Sprint 4 — Cross-Sprint Drift Check

> 第 4 个 Sprint 强制执行。来源：EvoClaw Drift 章节 + orchestrator L4 Hill Climbing。
> 输入：Sprint 3 `runtime-context.md` / `hill-climbing.md` / `progress.md`（Sprint+1 = lifecycle refactor 强信号）+ `/memories/repo/harness-backlog.md`（H6 pending, H7 新提案）+ `/memories/repo/lessons-learned.md`（L1-L11）。

## 1. Context Drift（工具链/环境漂移）

探针：`tmp/sprint4-survey.sh`（2026-07-29，make ebpf + go test 全 EXIT=0）。

| 项 | Sprint 3 基线 | Sprint 4 实测 | 漂移？ |
|----|--------------|--------------|--------|
| Go | go1.26.0 linux/amd64 | 同（survey go test 正常运行） | ❌ 无 |
| clang / bpftool | 18.1.3 / /usr/sbin/bpftool | 同（make ebpf EXIT=0） | ❌ 无 |
| kernel | 6.18.33.2-microsoft-standard-WSL2 | 同（同 WSL 实例，同日） | ❌ 无 |
| `.build_tags` | `trace` | `trace` | ❌ 无 |
| 分支 / 工作树 | kdae | kdae（survey 期间 clean） | ❌ 无 |
| **约束政策** | semantic_preserving（隐含） | **lifecycle_refactor_allowed**（用户显式解除） | ✅ **有意变更**（非漂移） |

**结论：零技术 Context Drift。** 唯一变更是**用户显式解除「语义等价」约束**（constraint_policy: lifecycle_refactor_allowed），这是计划内变更，使 Sprint 2/3 显式 deferred 的 lifecycle-boundary 候选（NewStreamSniffer / async-read / ExtractCryptoFrameOffset / NewLinearLocator）首次进入 scope。

## 2. Error Propagation（L1-L11 逐条对照 Sprint 4 plan）

| Lesson | 陷阱 | Sprint 4 规避 | 规避？ |
|--------|------|--------------|--------|
| L1 | 诚实 no-op 范式（需代码分析论证） | lifecycle 候选均有 CPU+memprofile flat% 双证据（G3+G4 gate），非静态 grep 猜测 | ✅ |
| L2 | desc 点名函数可能是生产死代码 | **G1 liveness 已验**：NewStreamSniffer←conn_sniffer.go:34（生产）/ readStreamOnceAsync←readStreamOnce←SniffTcp sniff loop / ExtractCryptoFrameOffset←ReassembleCryptos←sniffQuicBlock←SniffQuic / NewLinearLocator←quic.go:89。全 LIVE | ✅ |
| L7 | PowerShell 调 wsl 转义陷阱 | H3：全程 tmp/sprint4-survey.sh → `wsl bash`，无 inline `$` | ✅ |
| L8 | WSL2 可跑 make ebpf-test | 延续：survey make ebpf EXIT=0；ebpf-test gate 标 runs | ✅ |
| L9 | bench allocs ≠ 生产 allocs | 本 Sprint 不依赖单一 bench 数字；H7 CPU profile + H5 memprofile 双维度交叉验证 | ✅ |
| L10 | memprofile 优于 bench 数字（错误路径） | lifecycle 候选用 memprofile flat% 定位（NewStreamSniffer 11.31% / async.func1 16.04% flat>0=G4 通过），bench 仅作回归基线 | ✅ |
| L11 | Producer 阶段过滤 > Dev 阶段发现 | H7 CPU + H5 mem 在 Producer 阶段即跑（survey），harness noise（crypto 57%）源头排除 | ✅ |

**结论：L1-L11 全部规避。L2（G1 liveness）+ L11（Producer 阶段过滤）是本 Sprint 方法论核心。**

## 3. Tech Debt（Sprint 3 遗留 / Sprint+1 候选 → 本 Sprint 纳入）

| 来源 | 内容 | Sprint 4 处置 |
|------|------|--------------|
| Sprint 3 hill-climbing「Sprint+1 候选」 | sniffing lifecycle refactor：`NewStreamSniffer`（SniffTcp_TLS 11% flat）+ async-read goroutine（19%）池化；`ExtractCryptoFrameOffset` 跨调用存活、`NewLinearLocator` 装箱入 Locator 接口（3 Sprint 数据点） | **纳入本 Sprint 核心**（T1/T2/T3）—— 约束解除后首次可做 |
| Sprint 2 hill-climbing「Sprint+1 候选」 | ExtractCryptoFrameOffset 经 s.quicCryptas 跨调用存活 / NewLinearLocator 装箱入 Locator 接口（超语义等价边界） | **纳入 T2/T3** —— 同一 lifecycle 信号，第 3 次确认 |
| Sprint 3 progress「Bulk inherent」 | context/timer/struct/map 五项 inherent（udp_endpoint_pool） | 不涉及（本 Sprint 战场是 sniffing 包） |
| Sprint 3 OQ-S3-1/S3-2 | errStrLower 触发 / bulk 文档化 | 已闭环 ✅（Sprint 3 QA） |

**结论：3 个 Sprint 累积的 lifecycle refactor 信号（Sprint 2/3 hill-climbing 各记一次）首次进入 scope，是本 Sprint 主题的直接来源。**

## 4. Verification Fidelity（Sprint 3 commit 是否全被 gate 覆盖）

> 方法：`tmp/sprint4-survey.sh` §1，`git log 2cd90056..HEAD -- '*.go' '*.c'`（按 Sprint 3 边界 commit range，排除 _test.go/docs）。H6 应用：源码检测按扩展名（.go/.c），语言无关。

| Sprint 3 源码 commit | 触及源码文件（非 test） | plan target_files | 覆盖 gate | 门禁？ |
|----------------------|----------------------|-------------------|----------|--------|
| （Sprint 3 唯一源码改动） | control/udp_endpoint_pool.go | T1=control/udp_endpoint_pool.go ✅ | go_test(control)+race+vet+build+memprofile_review | ✅ gated |

**量化结论：**
- 源码 commit：1/1（udp_endpoint_pool.go）**100% 在 plan target_files 内且被 gate 覆盖**。
- `fidelity_risk: LOW（0% ungated）**。延续 Sprint 1/2/3 的 100% gated 记录。
- 注：verification-fidelity-check.ps1 实跑返回 43.1% ungated（HIGH_RISK），但这是 `-SinceDate` 默认 30 天窗口把 Sprint 1/2 的 daedns/client.go、sniffing/relocation.go 等也扫入所致（这些在 Sprint 1/2 plan 内 gated，但不在 Sprint 3 plan target_files 内）。**权威判定以 Sprint 边界 commit range 为准 = 0% ungated**。脚本 SinceDate 窗口问题记为 H6 残留改进（非本 Sprint 阻塞）。

## 5. Evals 回归检查（v4.1）

对 backlog 每个含 `eval` 字段、`applies_to_sprints` 含 Sprint 4、`check_timing ∈ {pre-sprint, both}` 的项，读 Sprint 3 progress.md Trace Log 匹配 `eval.regression_signal`：

| ID | eval.regression_signal | Sprint 3 Trace 匹配？ | 处置 |
|----|------------------------|----------------------|------|
| H1 | `ci_gate.*ignored` | ❌ 未命中：Sprint 3 gate 标 runs，实跑 make ebpf-test 8/8 PASS 3.224s | eval 通过 ✅ |
| H3 | `EXIT_(BUILD\|TEST)=True` | ❌ 未命中：Sprint 3 gate 全 PASS（vet/build/test/race EXIT=0） | eval 通过 ✅ |
| H5 | `harness.*allocs.*flat=0` | ❌ 未命中：Sprint 3 Producer 阶段 memprofile 过滤 WriteToBufferFlush（95.73% harness），0 harness-noise task；memprofile_review PASS（strings.ToLower cum 32768→0） | eval 通过 ✅（H5 持续生效） |
| H6 | （新应用，无前置回归信号） | — | 本 Sprint 首次应用（动态目录发现已生效），见 §6 |

**结论：H1/H3/H5 eval 全通过（改进持续生效），H6 首次应用。无 eval REGRESSION。**

## 6. H6 / H7 应用（本 Sprint）

### H6（pending → applied）verification-fidelity-check 语言无关化
- **现状核查**：脚本已含 `Get-ModulePrefixes`（v5.0 反过拟合改造）—— 动态扫描仓库目录发现 module 前缀，不再硬编码 `src/frontend/app/lib`。本次实跑确认能检测到 dae 的 `control/`、`component/` 下 .go 源码改动（不再返回假阴性 `PASS no_source_changes`）。
- **应用证据**：本次 drift-check §4 用按扩展名（.go/.c）的 git-log 权威方法（H6 方法论），非依赖 src/ 布局假设。
- **残留改进**（记 backlog，非阻塞）：`-SinceDate` 默认 30 天窗口过宽，应改为按 Sprint 边界 commit range（plan 锁定 from/to commit）。
- **backlog 标记**：H6 ✅ applied（Sprint 4），verified_in_sprint: 4。

### H7（新提案 → pending，本 Sprint 首次应用验证）
- **来源**：Sprint 3 仅用 bench + memprofile（H5，双维度：分配）。CPU 时间是第三维度，bench/memprofile 都不直接揭示 CPU 热点（哪个函数烧 CPU 最多）。
- **改进**：新增 `cpu_profile_review` gate——Producer 阶段跑 `-cpuprofile`，pprof `-top -cum` 列 hot path top 20，作为热点发现的第三维度。
- **本 Sprint 验证价值**（runtime-context.md §H7）：CPU profile 揭示 **GC 主导**（gcBgMarkWorker 27% + mallocgc 14% ≈ 41% 在 GC/mark）→ CPU 热点与 alloc 热点**收敛**（GC 压力源自分配）。这印证 lifecycle 重构（砍每连接 sniffer 分配）同时降低 CPU GC 时间，是 bench/memprofile 单独无法揭示的洞察。
- **backlog 标记**：H7 🟡 proposed（pending），本 Sprint 验证后标 applied。
