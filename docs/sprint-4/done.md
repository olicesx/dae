---
sprint: 4
sprint_theme: "Sniffing lifecycle refactor + CPU profile methodology (H7)"
verdict: PASS
commits_used: 3
commit_budget: 4
closed: 2026-07-29
branch: kdae
head_commit: 1e1fca20
content_language: bilingual
---

# Sprint 4 Done — 嗅探生命周期重构 + CPU Profile 方法论（H7）

> 收尾报告 / Wrap-up. 数据源：[progress.md](progress.md)、[hill-climbing.md](hill-climbing.md)、[../qa/qa-signoff-4.md](../qa/qa-signoff-4.md)。

## §1 主题与约束切换 / Theme & Constraint Switch

| 维度 | 内容 |
|------|------|
| 主题 | 嗅探（sniffing）生命周期重构 + CPU profile 方法论（H7） |
| 约束策略 | **首次解除「语义等价」约束**（`constraint_policy: lifecycle_refactor_allowed`，用户显式解除） |
| 方法论 | **首次引入 H7 CPU profile 第三维度**（bench/memprofile 之外） |
| 矿脉来源 | Sprint 1-3 三次 deferred 的 sniffing lifecycle-boundary 候选（Sprint 2/3 hill-climbing 各记一次） |
| 拓扑 | hybrid→sequential（降级：T1/T2/T3 共享 `component/sniffing/sniffer.go`，target_rules 无法互斥） |

> 双击开启新矿脉：解除约束 + 扩展维度同时进行。结果 T1/T2/T3 全有效，0 no-op（延续 Sprint 3）。

## §2 任务交付表 / Task Delivery

| Task | 内容 | commit | target_files | expected | actual |
|------|------|--------|--------------|----------|--------|
| T1 | Sniffer 对象池化 + async channel 复用（TCP+UDP 双路径） | `97d1c314` | sniffer.go, conn_sniffer.go(read-only) | effective_medium | ✅ effective（5 目标函数 mem flat 消除 + CPU 消除） |
| T3 | CryptoFrameOffset 跨调用存活（UDP） | `3bed4bef` | relocation.go, sniffer.go | effective_small | ✅ effective（ExtractCryptoFrameOffset flat 消除；ReassembleCryptos 2.26%→1.40%） |
| T2 | Locator 接口装箱消除（依赖 T1） | `1352dd85` | relocation.go, sniffer.go, quic.go, tls.go | effective_small | ✅ effective（BuiltinBytesLocator.Slice + NewLinearLocator + LinearLocator.Slice flat 全消除） |

- 实际改动文件（`git diff`）：sniffer.go / relocation.go / quic.go / tls.go / benchmark_test.go（conn_sniffer.go 列 T1 target 但实际 read-only 未改）。
- **Fidelity：源码改动 100% gated，0% ungated**（延续 Sprint 1-3 记录）。
- commits_used = 3/4（bug_reserve 未用 = 无 race/语义回归修复需要）。

## §3 Gate 结果汇总 / Gate Results

| Gate 组 | 结果 | 来源 |
|---------|------|------|
| **local_gate**（vet/build/test/race） | ✅ 全 PASS（race count=2 sniffing PASS，OQ-S4-1 闭环） | orchestrator-L2 复核（tmp/sprint4-l2.sh，全 EXIT=0） |
| **ci_gate**（ebpf-test / make ebpf / ebpf-sync-check） | ✅ 全 PASS（本 Sprint 无 .c 改动，回归安全）；ebpf_lint N/A | QA 独立补跑（tmp/qa-sprint4-gates.sh） |
| **manual_gate**（make dae / dae validate example+empty） | ✅ 全 PASS（L8：chmod 0600 临时副本） | QA 独立复核 |
| **cpu_profile_review（H7 新 gate）** | ✅ PASS | gcBgMarkWorker cum% 27.26%→10.32%（QA 独立复现 10.84%，噪声内一致）；mallocgc 不显著增；NewStreamSniffer CPU 层消除 |
| **interface_compatibility_check（lifecycle 新 gate）** | ✅ PASS | grep Locator/NewStreamSniffer/NewPacketSniffer 外部调用方：`control/packet_sniffer_pool.go` 等签名逐字不变，无破坏性变更 |
| memprofile_review（H5） | ✅ PASS | TLS+QUIC 5 目标函数 flat 全消除或下降 |

> **verdict = PASS**（local + ci + manual 全过）。依据签署规则无降级。

## §4 Benchmark 前后对比 / Benchmark Before vs After

> 7/7 全部下降，0 回归。来源：[progress.md](progress.md)「Benchmark 基线」表。

| Benchmark | 基线 allocs/op | 改动后 | Δ | 任务 |
|-----------|---------------|--------|---|------|
| Sniffer_SniffTcp_TLS | 18 (5294 B) | 13 (777 B) | **-5** | T1+T2 |
| Sniffer_SniffTcp_HTTP | 16 (5261 B) | 12 (761 B) | **-4** | T1 |
| Sniffer_SniffTcp_NotApplicable | 14 (5185 B) | 10 (705 B) | **-4** | T1 |
| SniffTcpReadStrategy/legacy_async_read | 14 (1112 B) | 13 (825 B) | **-1** | T1 |
| SniffTcpReadStrategy/deadline_sync_read | 8 | 5 (280 B) | **-3** | T1（生产 TCP 主路径） |
| Sniffer_SniffUdp_QUIC | 67 (7774 B) | 60 (5425 B) | **-7** | T1+T2+T3 |
| Sniffer_SniffUdp_QUICMultiPacket | 160 (23063 B) | 142 (14088 B) | **-18** | T1+T2+T3（跨调用存活收益最大） |

## §5 H7 CPU 收益 / H7 CPU Benefit

> 来源：[progress.md](progress.md)「H7 CPU profile 基线」表（Dev 报告值；QA 独立复现见注）。

| 函数 | 基线 cum% | 改动后 | Δ | 备注 |
|------|----------|--------|---|------|
| runtime.gcBgMarkWorker | 27.26% | **10.32%** | **-16.94** | H7 收益闭环核心：砍分配 → 降 GC mark CPU（bonus 强达成） |
| runtime.mallocgc | 14.20% | 14.30% | ~flat | inherent CRYPTO 分配主导（~71%），不可优化；OQ-S4-4「不增」marginally met |
| sniffing.NewStreamSniffer | 6.82% | **消除（出 top）** | **-6.82** | T1 池化，CPU 层确认 |
| sniffing.(*Sniffer).SniffTcp | 9.49% | 18.41% | +8.92（相对） | cum% 分母效应（GC 总量降致 APP 占比升），非回归 |
| sniffing.(*Sniffer).SniffQuic | 6.31% | 8.31% | +2.00（相对） | 同上（相对增长，非绝对回归） |

> QA 独立复现：gcBgMarkWorker 27.26%→10.84%（-16.42pp），与 Dev 10.32% 在 ±1pp 统计噪声内，**decisively 复现 H7 收益闭环**。

## §6 方法论复利 / Methodology Compounding

| 维度 | Sprint 1 | Sprint 2 | Sprint 3 | Sprint 4 |
|------|----------|----------|----------|----------|
| no-op 率 | 57% | 33% | 0% | **0%** |
| harness 改进 | H1-H4 | H1-H5 | H1-H6 | **H1-H8**（+H8 proposed, +H9 候选） |
| 方法论维度 | grep | bench | bench+memprofile | **bench+memprofile+CPU（三维度）** |
| 约束策略 | semantic-preserving | semantic-preserving | semantic-preserving | **lifecycle_refactor_allowed** |

- **H6 applied**（Sprint 4）：fidelity 语言无关化（drift-check §4 按扩展名 .go/.c/.rs git-log，修正原 `src/` 布局假设）。
- **H7 applied**（Sprint 4，强生效）：CPU profile 第三维度，揭示「GC 主导 CPU（41-50%）→ alloc 与 CPU 热点收敛」，催生 L12。
- **连续 2 Sprint 零 no-op、零 harness-noise task、零 L2 retry。**

## §7 Sprint+1 候选 / Sprint+1 Candidates

> 来源：[hill-climbing.md](hill-climbing.md) + qa-signoff-4 §8。lifecycle 重构矿脉仍丰饶。

| 候选 | 来源 | 方向 | 备注 |
|------|------|------|------|
| 长驻 reader goroutine（消除 per-call spawn） | OQ-S4-1 保守方案残留 / H7 async 调度开销 | lifecycle（高风险） | ⚠️ 触 OQ-S4-1 读语义风险，须完整 race + 语义对照 |
| sniffHTTPHostHeader + bytes.Index 纯 CPU | OQ-S4-3 / H7 CPU profile（cum 16.85% / 9.95%） | CPU 算法（非 alloc 驱动） | lifecycle 主题不覆盖，独立方向 |
| bench conn 改 deadline-supporting | L14 / H5 residual | harness 改进（H8 候选） | 消除 bytes.Reader 强制 async 偏差，使 memprofile 更贴近生产 |
| ReassembleCryptos merged slice 预分配 | §4.2 residual（1.40%） | alloc（marginal） | 收益 <1pp，低优先 |

## §8 Lessons 新增 / New Lessons

> 已写入 `/memories/repo/lessons-learned.md`（L12-L14）。详见 [hill-climbing.md](hill-climbing.md) §9 Reflexion。

| Lesson | 要点 |
|--------|------|
| **L12 CPU/GC 收敛** | CPU profile 揭示 GC 主导（gcBgMarkWorker 27%），alloc 与 CPU 热点收敛 → 砍分配同时降 GC CPU。判据须含 CPU 维度（gcBgMarkWorker cum% 下降 = 收益闭环）。 |
| **L13 pool + goroutine 守卫** | 对象池化须配套生命周期守卫（readerLingering 标志：超时残留 reader 不回收，避免 use-after-pool-put）；async goroutine 复用须保留读语义（顺序/超时/错误传播逐位一致）。 |
| **L14 cum%/flat% 相对值陷阱** | lifecycle 重构后 GC 总量骤降 → 分母缩小 → APP 函数 cum% 相对上升、inherent flat% 相对上升，**非回归**。判据 = 看 GC 类 cum% 是否下降 + 绝对 alloc_objects，不可单看 APP 百分比。延伸 L9：bench async 路径偏差（bytes.Reader 无 deadline → 强制 async），生产代表须用 deadline_sync_read bench。 |

> **验收范式**：lifecycle 重构须 cum%/flat% 相对值 + 绝对 alloc_objects + bench allocs/op + 生产路径分析四维交叉，不可单看百分比判回归。
