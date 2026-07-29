---
sprint: 5
check_type: cross-sprint-drift
run_by: Remy
run_at: 2026-07-29
prev_sprint: 4
sprint_theme: "Tech debt cleanup + measurement precision upgrade (H8 first application)"
constraint_policy: test_pruning_and_cpu_algo_allowed
verification_fidelity_method: authoritative-git-log
verification_fidelity_h6_applied: true
verification_fidelity_script_note: >
  H6 应用：脚本 Get-ModulePrefixes 动态目录发现已生效（能检测 .go 源码改动）。
  残留：-SinceDate 默认 30 天窗口过宽，实跑返回 44% ungated（HIGH_RISK），但这是把 Sprint 1/2/3/4
  的源码 commit（daedns/client.go、sniffing/relocation.go、control/udp_endpoint_pool.go、
  sniffing/sniffer.go 等）全扫入所致——这些在各自 Sprint plan target_files 内 gated，但不在 Sprint 4
  plan target_files 内。权威判定以 Sprint 边界 commit range 为准 = 0% ungated（见 §4）。
---

# Sprint 5 — Cross-Sprint Drift Check

> 第 5 个 Sprint 强制执行。来源：EvoClaw Drift 章节 + orchestrator L4 Hill Climbing。
> 输入：Sprint 4 `runtime-context.md` / `hill-climbing.md` / `done.md`（Sprint+1 三候选全纳入）+ `/memories/repo/harness-backlog.md`（H8 primary, H1-H7 持续）+ `/memories/repo/lessons-learned.md`（L1-L14）。

## 1. Context Drift（工具链/环境漂移）

探针：`tmp/sprint5-survey.sh`（2026-07-29，同 WSL 实例同日，与 Sprint 4 探针环境一致）。

| 项 | Sprint 4 基线 | Sprint 5 实测 | 漂移？ |
|----|--------------|--------------|--------|
| Go | go1.26.0 linux/amd64 | 同（survey go 命令正常运行） | ❌ 无 |
| clang / bpftool | 18.1.3 / /usr/sbin/bpftool | 同（本 Sprint 无 .c 改动，不触发） | ❌ 无 |
| kernel | 6.18.33.2-microsoft-standard-WSL2 | 同（同 WSL 实例，同日） | ❌ 无 |
| `.build_tags` | `trace` | `trace` | ❌ 无 |
| 分支 / 工作树 | kdae | kdae（survey 期间 clean） | ❌ 无 |
| **测试规模** | 203 test（S4 末） | 203 test（未变） | ❌ 无（T1 将首次缩减） |
| **约束政策** | lifecycle_refactor_allowed | **test_pruning_and_cpu_algo_allowed**（用户显式：首次删测试 + CPU 算法） | ✅ **有意变更**（非漂移） |

**结论：零技术 Context Drift。** 唯一变更是**用户显式开启「测试瘦身 + CPU 算法优化」新约束**，使 Sprint 4 done.md §7 的三个 Sprint+1 候选（sniffHTTPHostHeader CPU / bench conn deadline / 测试瘦身）首次进入 scope。测试瘦身是 Sprint 1-4 四次显式 deferred 的方向（S1-S4 非目标均列「测试瘦身」）。

## 2. Error Propagation（L1-L14 逐条对照 Sprint 5 plan）

| Lesson | 陷阱 | Sprint 5 规避 | 规避？ |
|--------|------|--------------|--------|
| L1 | 诚实 no-op 范式 | T2 reformulate 后若 http.go 无可优化空间须诚实标 no-op（OQ-S5-1）；T1/T3 是确定性改进非 no-op 风险点 | ✅ |
| L2 | desc 点名函数可能是生产死代码 | T2 G1 已验：sniffHTTPHostHeader←SniffHttp←生产嗅探（LIVE） | ✅ |
| L7 | PowerShell 调 wsl 转义陷阱 | H3：全程 tmp/sprint5-*.sh → `wsl bash`，无 inline `$`（survey/t1-categorize 均脚本化） | ✅ |
| L8 | WSL2 可跑 make ebpf-test | 延续：ci_gate 标 runs（本 Sprint 无 .c 改动，回归安全） | ✅ |
| L9 | bench allocs ≠ 生产 allocs | T3 核心——bytes.Reader 强制 async 路径正是 L9 延伸（L14）；H8 首次应用修复 | ✅ |
| L10 | memprofile 优于 bench 数字 | T2 用 H7 CPU profile + H5 memprofile 双维度，非单一 bench | ✅ |
| L11 | Producer 阶段过滤 > Dev 阶段发现 | T2 前提核查在 Producer 阶段即发现「用户描述 vs 实际不符」（OQ-S5-1），reformulate 而非传给 Dev 盲做 | ✅ |
| L12 | CPU/GC 收敛 | T2 是纯 CPU 算法（非 GC 驱动），H7 verdict 用 CPU cum% 判；与 S4 lifecycle 的 alloc→GC 路径不同维度 | ✅ |
| L13 | pool + goroutine 守卫 | T2 不碰池化（scope_lock 明示），L13 不触发；若 Dev 评估需池化须加守卫 | ✅ |
| L14 | cum%/flat% 相对值陷阱 + bench async 偏差 | T3 直接修复 L14 的 bench async 偏差（H8 首次应用）；T2 verdict 不可单看 cum% 相对值 | ✅ |

**结论：L1-L14 全部规避。L9+L14（bench async 偏差）是 T3 核心；L11（Producer 阶段过滤）在 T2 前提核查生效。**

## 3. Tech Debt（Sprint 4 遗留 / Sprint+1 候选 → 本 Sprint 纳入）

| 来源 | 内容 | Sprint 5 处置 |
|------|------|--------------|
| Sprint 4 done.md §7 / hill-climbing「Sprint+1 候选」 | sniffHTTPHostHeader + bytes.Index 纯 CPU（OQ-S4-3） | **纳入 T2** —— H7 CPU 矿脉首次开采（非 lifecycle/alloc 维度） |
| Sprint 4 done.md §7 / hill-climbing「Sprint+1 候选」 | bench conn 改 deadline-supporting（L14/H8） | **纳入 T3** —— H8 首次应用，修复 async 偏差 |
| Sprint 4 qa-signoff-4 §8 / Sprint 1-4 非目标 | 测试瘦身（4 Sprint 显式 deferred） | **纳入 T1** —— 用户首次解锁，203→~100 目标 |
| Sprint 4 hill-climbing「Sprint+1 候选」 | 长驻 reader goroutine（lifecycle 高风险） | **不纳入** —— 触 OQ-S4-1 读语义风险，需独立 lifecycle Sprint |
| Sprint 4 hill-climbing「Sprint+1 候选」 | ReassembleCryptos merged slice 预分配（<1pp） | **不纳入** —— 收益 marginal，低优先 |
| harness-backlog H8（pending） | bench harness 路径代表性 | **T3 首次应用** —— backlog pending→applied |
| harness-backlog H9（candidate） | task DAG target_files 重叠检测 | **评估应用** —— T1/T3 sniffing 包耦合确认，强制 sequential |

**结论：Sprint 4 的三个 Sprint+1 候选（CPU 算法 / bench harness / 测试瘦身）全部纳入，是本 Sprint 主题的直接来源。lifecycle 矿脉暂停（长驻 reader goroutine 高风险 defer）。**

## 4. Verification Fidelity（Sprint 4 commit 是否全被 gate 覆盖）

> 方法：`git log 1e1fca20..HEAD` 无新增（Sprint 4 后未 commit）；权威方法 `git log <sprint4-start>..1e1fca20 -- '*.go'`（按 Sprint 4 边界 commit range，排除 _test.go/docs）。H6 应用：源码检测按扩展名（.go）。

| Sprint 4 源码 commit | 触及源码文件（非 test） | plan target_files | 覆盖 gate | 门禁？ |
|----------------------|----------------------|-------------------|----------|--------|
| 97d1c314 (T1) | component/sniffing/sniffer.go | T1=sniffer.go ✅ | go_test+race+vet+build+cpu_profile+interface_compat | ✅ gated |
| 3bed4bef (T3) | component/sniffing/internal/quicutils/relocation.go, sniffer.go | T3=relocation.go,sniffer.go ✅ | 同上 | ✅ gated |
| 1352dd85 (T2) | relocation.go, sniffer.go, quic.go, tls.go | T2=relocation.go,sniffer.go,quic.go,tls.go ✅ | 同上 | ✅ gated |

**量化结论：**
- 源码 commit：3/3（sniffer.go / relocation.go / quic.go / tls.go）**100% 在 Sprint 4 plan target_files 内且被 gate 覆盖**。
- `fidelity_risk: LOW（0% ungated）**。延续 Sprint 1-4 的 100% gated 记录。
- 注：verification-fidelity-check.ps1 实跑返回 44% ungated（HIGH_RISK），这是 `-SinceDate` 默认 30 天窗口把 Sprint 1/2/3 的源码 commit（daedns/client.go、control/udp_endpoint_pool.go 等）也扫入所致（这些在各自 Sprint plan 内 gated，但不在 Sprint 4 plan target_files 内）。**权威判定以 Sprint 边界 commit range 为准 = 0% ungated**。脚本 SinceDate 窗口问题记为 H6 残留改进（非本 Sprint 阻塞，已连续 2 Sprint 记录）。

## 5. Evals 回归检查（v4.1）

对 backlog 每个含 `eval` 字段、`applies_to_sprints` 含 Sprint 5、`check_timing ∈ {pre-sprint, both}` 的项，读 Sprint 4 progress.md Trace Log 匹配 `eval.regression_signal`：

| ID | eval.regression_signal | Sprint 4 Trace 匹配？ | 处置 |
|----|------------------------|----------------------|------|
| H1 | `ci_gate.*ignored` | ❌ 未命中：Sprint 4 gate 标 runs，QA 实跑 make ebpf-test EXIT=0 | eval 通过 ✅ |
| H3 | `EXIT_(BUILD\|TEST)=True` | ❌ 未命中：Sprint 4 gate 全 PASS（vet/build/test/race EXIT=0） | eval 通过 ✅ |
| H5 | `harness.*allocs.*flat=0` | ❌ 未命中：Sprint 4 Producer 阶段 memprofile flat% 驱动（NewStreamSniffer 11.31% 等），0 harness-noise task；memprofile_review PASS（5 目标函数 flat 消除） | eval 通过 ✅（H5 持续生效） |
| H6 | （S4 首次应用，无前置回归信号） | — | 持续应用（动态目录发现生效，SinceDate 窗口为非阻塞残留） |
| H7 | （S4 首次应用，无前置回归信号） | — | 持续应用（T2 verdict 必须含 CPU 维度） |

**结论：H1/H3/H5 eval 全通过（改进持续生效），H6/H7 持续应用，H8 本 Sprint 首次应用。无 eval REGRESSION。**

## 6. H8 应用（本 Sprint 首次）+ backlog 应用清单

### H8（pending → applied，本 Sprint 首次应用）bench harness 路径代表性
- **现状核查**：component/sniffing/benchmark_test.go @18/38/125 三处 `NewStreamSniffer(bytes.NewReader(...), timeout)` —— bytes.NewReader 实现 io.Reader 但不支持 SetReadDeadline → sniffer.go:160 readStreamOnce 走 readStreamOnceAsync（@194 spawn goroutine + channel）而非生产 deadline_sync_read（@170）。
- **生产对照**：sniffer.go:170 `s.conn.SetReadDeadline(s.deadline)` 是生产 TCP 主路径（S4 done.md: deadline_sync_read=5 allocs vs legacy_async_read=13）。
- **应用证据**：T3 把 bytes.NewReader 替换为 deadline-supporting conn（net.Pipe+SetReadDeadline 或 deadlineConn 包装），使 bench 走 deadline_sync_read 路径，memprofile 不再被 async 偏差污染。
- **backlog 标记**：H8 ✅ applied（Sprint 5），verified_in_sprint: 5。

### Sprint 5 backlog 应用清单（harness-backlog「Sprint 5 application preview」逐项）

| Item | Apply in S5? | 如何应用 | 应用记录 |
|------|---|---|---|
| H1 | yes | T1 验证三件套 go test ./... 实跑；ci_gate make ebpf-test 实跑不 ignored | ✅ applied（plan gates ci_gate_ebpf_test target=pass note=H1） |
| H3 | yes | 全程 tmp/sprint5-*.sh（survey/t1-categorize），无 inline $ | ✅ applied（drift §1 探针 + progress Trace 记录） |
| H4 | yes | T1 target_files 含关联 helper 文件（删除候选的依赖链） | ✅ applied（plan T1 target_files KEEP helpers 段） |
| H5 | yes | T2 memprofile 交叉验证（CPU 驱动任务的 alloc 旁证） | ✅ applied（plan gates memprofile_review + T2 G4 conditional） |
| H6 | yes | fidelity 按扩展名 .go（Sprint 5 仅改 .go） | ✅ applied（drift §4 按 .go git-log） |
| H7 | yes | T2 verdict 必须含 CPU 维度（不能用 bench allocs 判） | ✅ applied（plan gates cpu_profile_review target=sniffHTTPHostHeader_cum_drop + T2 h7_verdict_dimension） |
| **H8** | **yes — primary** | T3 bench harness deadline 化（三方向之一） | ✅ **首次 applied**（plan gates h8_deadline_sync_verification target=>=3 + T3 h8_application） |
| H9 | evaluated | T1/T3 sniffing 测试包耦合 → 强制 sequential | ✅ 评估应用（plan topology_rationale + task_sizing strong_coupling=1） |
