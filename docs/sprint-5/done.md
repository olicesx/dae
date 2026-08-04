---
sprint: 5
sprint_theme: "Tech debt cleanup + measurement precision upgrade (H8 first application) / 技术债清理 + 测量精度升级（H8 首次应用）"
verdict: PASS
verdict_history: "CONDITIONAL (QA first pass, ci_gate_ebpf_test FAIL) → PASS (orchestrator L2-retry verify, make ebpf-test EXIT=0)"
commits_used: 5
commit_budget: 5
closed: 2026-07-29
branch: kdae
head_commit: 722b123b
content_language: bilingual
---

# Sprint 5 Done — 技术债清理 + 测量精度升级（H8 首次应用）

> 收尾报告 / Wrap-up. 数据源：[progress.md](progress.md)、[hill-climbing.md](hill-climbing.md)、[../qa/qa-signoff-5.md](../qa/qa-signoff-5.md)。

## §1 主题与约束切换 / Theme & Constraint Switch

| 维度 | 内容 |
|------|------|
| 主题 | 技术债清理（AI 批量测试瘦身 + CPU 算法优化 + bench harness 测量精度） |
| 约束策略 | **首次解除「测试瘦身 + CPU 算法」约束**（`constraint_policy: test_pruning_and_cpu_algo_allowed`，用户显式解除） |
| 约束解除记录 | Sprint 1-4 四次显式 deferred「测试瘦身」；Sprint 5 首次解锁。CPU 算法（sniffHTTPHostHeader）是 Sprint 4 OQ-S4-3 矿脉。 |
| 方法论 | **首次应用 H8**（bench harness deadline 化）+ **首次主动应用 H9**（Producer 规划阶段判 target_files 重叠） |
| 矿脉来源 | Sprint 4 done.md §7 三候选全纳入（CPU 算法 / bench harness / 测试瘦身）+ Sprint 1-4 四次 deferred 的测试瘦身 |
| 拓扑 | sequential（H9 主动：T1/T3 sniffing 测试包编译耦合，规划阶段直接 sequential，0 降级事件） |

> 首次矿脉切换到 tech-debt cleanup：T1/T2/T3 全有效，0 no-op（延续 Sprint 3-4）。

## §2 任务交付表 / Task Delivery

| Task | 内容 | commit | target_files | expected | actual |
|------|------|--------|--------------|----------|--------|
| T1 | AI 批量测试瘦身（删 108 / 留 90 + 恢复 3 helper + 3 bulk-infra） | `0e673fe7` | 108 deleted + 3 new helpers + edits to existing helpers | test:src 1.03→~0.5 | ✅ **1.03→0.490**（达标） |
| T2 | sniffHTTPHostHeader CPU 热路径优化（IndexByte 行分割 + 跳 request line + 消 string alloc） | `1d1021eb` | component/sniffing/http.go | effective_small | ✅ **effective**（Extended -36% / NoHost -43%；bytes.Index cum 57.92%→8.66%） |
| T3 | H8 首次应用：bench harness deadline 化（自定义 deadlineConn） | `d3e5c4a2` | component/sniffing/benchmark_test.go | bench SniffTcp 趋近 deadline_sync 基线 | ✅ **effective**（HTTP 5 / TLS 6 / NotApplicable 3，原 async ~12） |

- **docs commit**：`828afae5`（sprint-5 文档）。
- **L2 retry fix**：`722b123b`（恢复 `control/bpf_bug_verification_test.go`，ISSUE-1 ci_gate 回归修复）。
- 实际改动文件（`git diff`）：108 测试删除 + 3 新集中 helper 文件 + 3 恢复 bulk-infra 文件 + `component/sniffing/http.go`(+45/-10) + `component/sniffing/benchmark_test.go`(+43/-3) + 恢复 `control/bpf_bug_verification_test.go`。
- **Fidelity：源码改动 100% gated，0% ungated**（延续 Sprint 1-4 记录）。
- commits_used = 5/5（3 task code + 1 docs + 1 L2-retry fix）。bug_reserve=1 正确覆盖 L2 retry。

## §3 Gate 结果汇总 / Gate Results

| Gate 组 | 结果 | 来源 |
|---------|------|------|
| **local_gate**（vet/build/test/race） | ✅ 全 PASS（race count=2 sniffing+control PASS；19 包 ok / 0 FAIL） | orchestrator-L2 复核（全 EXIT=0） |
| **ci_gate**（ebpf-test / make ebpf / ebpf-sync-check） | ✅ 全 PASS（**经 L2 retry**：ISSUE-1 修复后 make ebpf-test EXIT=0） | QA 首跑 FAIL → L2 retry Dev 修复 722b123b → orchestrator 独立复核 EXIT=0 |
| **manual_gate**（make dae / dae validate example+empty） | ✅ 全 PASS（L8：chmod 0600 临时副本） | QA 独立复核 |
| **deletion_protection_check（T1）** | ✅ PASS | 108 删除全在批量 commit，原生 16 零触碰（comm -12 验证） |
| **test_src_ratio（T1）** | ✅ PASS | 1.03→0.490（target ~0.5） |
| **cpu_profile_review（H7，T2 决定性）** | ✅ PASS | bytes.Index cum 57.92%→8.66%（QA 复现 8.72%，±1pp）；IndexByte 走 indexbytebody 汇编 |
| **memprofile_review（H5，T2 旁证）** | ✅ PASS | Extended 1 alloc（Host string inherent）/ NoHost 0 alloc |
| **h8_deadline_sync_verification（H8 首次，T3 决定性）** | ✅ PASS | readStreamOnceWithReadDeadline 出现 / readStreamOnceAsync 零出现（pprof 确认）；allocs HTTP 5/TLS 6/NotApplicable 3 |

> **verdict = PASS（升级自 CONDITIONAL）**。QA 首跑 CONDITIONAL（ci_gate_ebpf_test FAIL），L2 retry 修复 ISSUE-1 后升级 PASS。依据签署规则：local+ci+manual 全过。

## §4 Benchmark 前后对比 / Benchmark Before vs After

> T2 CPU 收益 + T3 harness 精度提升。0 回归。来源：[progress.md](progress.md)。

### T2 — sniffHTTPHostHeader（H7 CPU 算法）

| Benchmark | baseline ns/op | after ns/op | Δ | allocs |
|-----------|---------------|-------------|---|--------|
| Extended（含 Host） | 126.5 | 80.91 | **-36%** | 1（Host string inherent） |
| NoHost | 57.66 | 32.82 | **-43%** | 0 |
| bytes.Index cum%（H7 决定性） | 57.92% | 8.66% | **-49pp** | — |

### T3 — bench harness deadline 化（H8 首次应用）

| Benchmark | 原 async allocs | deadline-sync allocs | Δ | 备注 |
|-----------|----------------|---------------------|---|------|
| SniffTcp_HTTP | ~12 | **5** | -7 | 精确等于 S4 deadline_sync_read 基线 |
| SniffTcp_TLS | ~12 | **6** | -6 | — |
| SniffTcp_NotApplicable | ~12 | **3** | -9 | — |

> H8 收益闭环：bench 数字变化是预期的测量精度提升（趋近生产 deadline_sync 基线），非性能回归。后续 perf Sprint 的 memprofile 不再被 async 偏差污染。

## §5 H8/H9 收益 / H8/H9 Benefit

| 维度 | Sprint 4（H8/H9 前） | Sprint 5（H8/H9 后） | 收益 |
|------|---------------------|---------------------|------|
| bench 路径代表性 | bytes.Reader 强制 async（~13 allocs），掩盖生产 TCP 真实分配 | deadlineConn 走 deadline_sync（5 allocs），精确等于生产基线 | **测量精度提升**（H8 首次应用） |
| 拓扑决策 | Producer 规划 hybrid，执行期降级 sequential（返工） | Producer 规划阶段就 sequential（H9 主动） | **0 降级事件**（H9 首次主动应用） |

## §6 方法论复利 / Methodology Compounding

| 维度 | Sprint 1 | Sprint 2 | Sprint 3 | Sprint 4 | Sprint 5 |
|------|----------|----------|----------|----------|----------|
| no-op 率 | 57% | 33% | 0% | 0% | **0%** |
| harness 改进 | H1-H4 | H1-H5 | H1-H6 | H1-H8 | **H1-H10**（+H8/H9 applied, +H10 proposed） |
| 方法论维度 | grep | bench | bench+mem | +CPU | **+tech-debt cleanup（测试瘦身方法论）** |
| 约束/矿脉 | semantic | semantic | semantic | lifecycle | **tech-debt cleanup** |
| L2 retry | 0 | 0 | 0 | 0 | **1（修复成功，bug_reserve 正确覆盖）** |
| topology | serial | serial | serial | hybrid→seq | **sequential（H9 主动）** |

- **H8 applied**（Sprint 5 首次）：bench harness deadline 化，修复 L14 async 偏差。
- **H9 applied**（Sprint 5 首次主动）：Producer 规划阶段判 target_files 重叠，0 降级事件。
- **连续 3 Sprint 零 no-op**（S3-S5）：跨矿脉（perf/lifecycle/tech-debt）持续，方法论已矿脉无关。

## §7 Sprint+1 候选 / Sprint+1 Candidates

> 来源：[hill-climbing.md](hill-climbing.md) + qa-signoff-5 §8。

| 候选 | 来源 | 方向 | 备注 |
|------|------|------|------|
| H10 应用（deletion_protection gate 增强） | L16（Makefile/CI 盲区） | harness 改进 | 删前扫 Makefile/.github 引用；适用条件：未来 Sprint 涉文件删除 |
| 巨型文件拆分（control_plane.go 4040 / dns_control.go 3318 / udp_endpoint_pool.go 2360） | Sprint 1 deferred + S5 测试瘦身降风险 | 架构重构 | ⚠️ 需新 Sprint 类型（非 perf 非技术债清理） |
| eBPF tproxy.c 再精简 | Sprint 1 B1/B2 no-op 后剩余 | 内核态 perf | 需 clang IR 分析；bench 难测但有理论收益 |
| 长驻 reader goroutine | OQ-S4-1 / H7 async 调度开销 | lifecycle（高风险） | 触读语义风险，需独立 lifecycle Sprint |
| 恢复原生 quic_bench/sniffing_bench_test.go | qa-signoff-5 §3.1 plan 陈旧条目 | 数据修正 | 被 #970 删除的原生 bench，git 历史可恢复 |

## §8 Lessons 新增 / New Lessons

> 已写入 `/memories/repo/lessons-learned.md`（L15-L17）。详见 [hill-climbing.md](hill-climbing.md) §模式识别。

| Lesson | 要点 |
|--------|------|
| **L15 helper 链深度** | 测试瘦身的 helper 依赖链可达 ~5 层簇（scripted family → errorDialer → ... → corpus）。诊断法：`go test -run='^$'` 一次性 surface 全部 undefined（而非迭代 vet）。 |
| **L16 Makefile/CI 盲区** | deletion_protection 不能只查 Go import 依赖 + 原生保护，必须扫构建系统（Makefile/.github/workflows）引用。build-tag 门控文件（`dae_bpf_tests`）对 `go test` 不可见但被 Makefile `go generate` 引用 → 只有 `make ebpf-test` 抓到断裂。 |
| **L17 gitignored bpf 生成文件** | gitignored bpf objects 生成文件（`bpfObjects`）曾缺失致 `go vet` 误报 undefined，`make ebpf` 重新生成后全过。这是环境状态（区别于 L16 的构建系统依赖），须与真实回归区分。 |

> **ISSUE-1（L2 retry）记录**：T1 误删 `control/bpf_bug_verification_test.go`（Makefile 行 136/151/166/181 的 `go generate` 依赖）。`go vet`/`go test ./...` 抓不到（build tag `dae_bpf_tests` 默认不可见），只有 `make ebpf-test` 抓到（EXIT=2）。修复：`git checkout 0e673fe7^ -- control/bpf_bug_verification_test.go`（commit 722b123b）。催生 L16 → H10 因果链。
