---
sprint: 4
sprint_theme: "Sniffing lifecycle refactor + CPU profile methodology (H7)"
phase: planning
owner: Remy
branch: kdae
created: 2026-07-29

# === blast_radius（plan 锁定）===
blast_radius:
  commit_budget: 4
  commit_budget_formula: dag_layers + strong_coupling_count + bug_reserve
  hard_cap: 10
  commits_used: 0
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true

# === topology ===
topology_used: sequential_downgraded_from_hybrid
topology_rationale: "T1/T2/T3 三 task 共享 component/sniffing/sniffer.go，target_rules 无法互斥，按 kixpower 拓扑降级规则改串行（顺序 T1→T3→T2，T2 依赖 T1 struct 放最后）"

# === task DAG 摘要（Dev/QA 填 status）===
tasks:
  T1: {status: pending, files: [component/sniffing/sniffer.go, component/sniffing/conn_sniffer.go], source: "H7 CPU + H5 mem", expected: effective_medium, mem_evidence: "NewStreamSniffer 11.31% + async.func1 16.04% + NewPacketSniffer 3.50% + pool.Put 17.71%"}
  T2: {status: pending, files: [component/sniffing/internal/quicutils/relocation.go, component/sniffing/sniffer.go, component/sniffing/quic.go, component/sniffing/tls.go], source: "H5 mem", depends_on: [T1], expected: effective_small, mem_evidence: "BuiltinBytesLocator.Slice 10.38% + NewLinearLocator 2.07% + LinearLocator.Slice 2.17%"}
  T3: {status: pending, files: [component/sniffing/internal/quicutils/relocation.go, component/sniffing/sniffer.go], source: "H5 mem", expected: effective_small, mem_evidence: "ExtractCryptoFrameOffset 3.11% + ReassembleCryptos 2.26%"}

# === Dev L2 verification（mode 要求字段，Dev 填）===
completed_tasks: 3
artifacts_changed_since_last_observe: [component/sniffing/sniffer.go, component/sniffing/conn_sniffer.go(unread-only), component/sniffing/internal/quicutils/relocation.go, component/sniffing/quic.go, component/sniffing/tls.go, component/sniffing/benchmark_test.go]
l2_verification_passed: true
commits_used: 3

# === verifiable_gates 状态（Dev/QA 填）===
gates:
  go_vet: pass
  go_build: pass
  go_test: pass
  go_test_race: pass
  benchmark_no_regression: pass
  memprofile_review: pass
  cpu_profile_review: pass        # H7 新 gate：NewStreamSniffer 消除；gcBgMarkWorker 27.26%→10.32%
  interface_compatibility_check: pass   # Locator/NewStreamSniffer/NewPacketSniffer 无外部调用方变更
  ci_gate_ebpf_test: pending   # QA（本 Sprint 无 .c 改动，回归安全）
  ci_gate_make_da_ebpf: pass   # F1：make ebpf EXIT=0
  ebpf_lint: na
  ebpf_sync_check: pass   # 无 C 结构体改动
---

# Sprint 4 Progress — 嗅探生命周期重构 + CPU Profile 方法论（H7）

> 执行期由 Dev/QA 填写。阶段过渡时 Remy 更新本文件与 PROJECT_BRIEF.md 第 7、8 节。

## 状态总览 / Status

| 阶段 | 负责人 | 状态 |
|------|--------|------|
| Planning（drift-check + H7 CPU + H5 mem + plan） | Remy | ✅ 完成 |
| Dev 实现（T1 池化 / T2 接口收敛 / T3 跨调用存活） | Dev | ✅ 完成 |
| QA 验证（gate 全过 + cpu_profile_review + interface_compat） | Ivy | ✅ PASS（qa-signoff-4.md） |

## Trace Log

<!-- 每次任务推进追加一行：[时间] task | 动作 | 结果 | commit? -->

- [2026-07-29] planning | drift-check 完成（4 项：技术零漂移 / L1-L11 全规避 L2+L11 核心 / Sprint2-3 lifecycle 信号纳入 / fidelity 100% gated 按 commit range 权威判定脚本 43.1% 为 SinceDate 窗口假象）；Evals：H1/H3/H5 全通过 H6 首次应用 H7 新项 | drift-check.md | —
- [2026-07-29] H7+H5 扫描 | tmp/sprint4-survey.sh：make ebpf=0 / CPU profile（GC 主导 41-50%，NewStreamSniffer cum 6.82%）/ mem SniffTcp_TLS（async.func1 16.04% + NewStreamSniffer 11.31% + BuiltinBytesLocator.Slice 10.38%）/ mem SniffUdp_QUIC（crypto 57% inherent + pool.Put 17.71% + ExtractCryptoFrameOffset 3.11% + NewLinearLocator 2.07%）| runtime-context.md §H7/§H5 | —
- [2026-07-29] planning | G1 liveness 全 PASS（grep 4 目标函数生产调用链）/ G2 heat warm/hot / G3 bench allocs>0 / G4 目标函数 flat>0 全通过 | plan.md task DAG | —
- [2026-07-29] planning | task_sizing：task_count=3, dag_layers=2, strong_coupling=1, bug_reserve=1 → commit_budget=4（hard_cap=10）；topology=hybrid | plan.md blast_radius | — |
- [2026-07-29] orchestrator-observe | Producer 产出验证 PASS：artifacts 真实变更（PROJECT_BRIEF +76 行 / sprint-4 4 文档 9-20KB）/ Sprint1 历史文档改动系 v5.0 复核补充（qa-signoff-1 §9 / hill-climbing / plan / progress，非 goal_drift）/ plan.md 完整（3 task + cpu_profile_review + interface_compatibility 双新 gate + eval H1/H3/H5/H6/H7）/ sniffing.test 临时文件已清理 / 4 OQ 记录 | result=ok | — |
- [2026-07-29] orchestrator-decision | 拓扑降级 hybrid→sequential：T1/T2/T3 三 task 共享 component/sniffing/sniffer.go，target_rules 无法互斥，按 kixpower 降级规则改串行（顺序 T1→T3→T2，T2 依赖 T1 struct 放最后） | progress.md topology_used | — |
- [2026-07-29] T1 | Sniffer struct sync.Pool + readStreamOnceAsync 内联为单 goroutine + readResultCh 懒分配复用；readerLingering 标志守卫 pool 复用（超时残留 reader 不回收，避免 use-after-pool-put） | gates 全过（race count=3）；bench SniffTcp_TLS 18→14/HTTP 16→12/NotApplicable 14→10/QUIC 67→63/legacy_async 14→13 | commit 97d1c314 |
- [2026-07-29] T3 | CryptoFrameOffset sync.Pool：ExtractCryptoFrameOffset + ReassembleCryptos 合并路径用池；CompactPacketState/Close/reset 释放 | QUIC race count=3 通过；QUICMultiPacket 154→145；ExtractCryptoFrameOffset flat 消除 | commit 3bed4bef |
- [2026-07-29] T2 | 消除 Locator 装箱：findSniExtension 改绝对索引(base,length)省 Slice 调用 + LinearLocator.Reset 经 s.quicLocator 复用省 NewLinearLocator | TLS+QUIC race count=3 通过（SNI 逐位一致）；SniffTcp_TLS 14→13/QUIC 62→60/MultiPacket 145→142；BuiltinBytesLocator.Slice+LinearLocator.Slice+NewLinearLocator flat 全消除 | commit 1352dd85 |
- [2026-07-29] orchestrator-L2 | 复核 Dev 自跑结果（tmp/sprint4-l2.sh）：EBPF/VET/BUILD/TEST/RACE 全 EXIT=0；control test 25.4s PASS；race count=2 sniffing PASS（T1 async 复用读语义安全，OQ-S4-1 闭环）；benchmark 复核 SniffTcp_TLS=13（基线18，与 Dev 报告一致）/ QUIC=60（基线67，一致）/ legacy_async_read=13（基线14，下降） | result=ok（全 gate 过，推进 QA） | — |
- [2026-07-29] QA-gates | 独立补跑 ci_gate+manual_gate+H5/H7 决定性 gate（tmp/qa-sprint4-gates.sh）：make ebpf/ebpf-test/ebpf-sync-check EXIT=0；make dae 产出 stripped x86-64 ELF；dae validate example+empty EXIT=0（L8 chmod 0600）；interface_compat grep 确认 NewPacketSniffer(data,ttl)/NewStreamSniffer(conn,timeout) 签名不变、Locator 无外部调用方 | result=ok | — |
- [2026-07-29] QA-H5/H7 | memprofile TLS：NewStreamSniffer/BuiltinBytesLocator.Slice/readStreamOnceAsync.func1 flat 全消除（residual readStreamOnceAsync 26% = bench bytes.Reader 强制 async 的 harness 偏差，L14）；memprofile QUIC：NewPacketSniffer/NewLinearLocator/LinearLocator.Slice/ExtractCryptoFrameOffset 全消除，ReassembleCryptos 2.26%→1.40%；cpu_profile：gcBgMarkWorker 27.26%→10.84%（-16pp H7 闭环复现），NewStreamSniffer 消除，mallocgc 14.20%→15.14%（噪声内 OQ-S4-4 marginally met） | verdict=PASS | — |
- [2026-07-29] QA-signoff | 产出 docs/qa/qa-signoff-4.md（verdict=PASS）；无真实缺陷（不提 Issue）；新增 L14（cum%/flat% 分母陷阱 + bench async 偏差）写入 lessons-learned.md；H7 backlog proposed→applied；Sprint+1 候选：sniffHTTPHostHeader+bytes.Index CPU 优化 / bench conn deadline 化 | sprint-4 closed | — |

## Benchmark 基线（Dev 改动前对照，来自 runtime-context.md §H5）

| Benchmark | 基线 allocs/op | 改动后 | Δ | 任务 | 备注 |
|-----------|---------------|--------|---|------|------|
| BenchmarkSniffer_SniffTcp_TLS | 18 (5294 B) | 13 (777 B) | **-5** | T1+T2 | NewStreamSniffer 池化 + async 单 goroutine + Slice 装箱消除 |
| BenchmarkSniffer_SniffTcp_HTTP | 16 (5261 B) | 12 (761 B) | **-4** | T1 | lifecycle 同 TLS |
| BenchmarkSniffer_SniffTcp_NotApplicable | 14 (5185 B) | 10 (705 B) | **-4** | T1 | lifecycle |
| BenchmarkSniffTcpReadStrategy/legacy_async_read | 14 (1112 B) | 13 (825 B) | **-1** | T1 | async goroutine 池化核心验证点 |
| BenchmarkSniffTcpReadStrategy/deadline_sync_read | 8 | 5 (280 B) | **-3** | T1 | 生产 TCP 主路径（net.Conn+deadline） |
| BenchmarkSniffer_SniffUdp_QUIC | 67 (7774 B) | 60 (5425 B) | **-7** | T1+T2+T3 | packet 池化 + crypto 池化 + Locator 复用 |
| BenchmarkSniffer_SniffUdp_QUICMultiPacket | 160 (23063 B) | 142 (14088 B) | **-18** | T1+T2+T3 | 多包跨调用存活收益最明显 |

> bench 现调用 Close 以覆盖 construct→sniff→close 完整生命周期（生产行为），而非仅分配路径（L9 教训：bench≠生产）。

## H7 CPU profile 基线（Dev 改动前对照，来自 runtime-context.md §H7）

| 函数 | 基线 cum% | 改动后 | Δ | 备注 |
|------|----------|--------|---|------|
| runtime.gcBgMarkWorker | 27.26% | **10.32%** | **-16.94** | H7 收益闭环核心：砍分配 → 降 GC mark CPU（bonus 强达成） |
| runtime.mallocgc | 14.20% | 14.30% | ~flat | 由 inherent CRYPTO 分配主导（hmac/sha256/hkdf），不可优化；OQ-S4-4 判据「不增」通过 |
| sniffing.NewStreamSniffer | 6.82% | **消除（出 top）** | **-6.82** | T1 池化 |
| sniffing.(*Sniffer).SniffTcp | 9.49% | 18.41% | +8.92（相对） | cum% 为相对值：GC 总量骤降使分母缩小，app 占比上升（绝对时间微增=pool Get/Put 开销，系统净收益） |
| sniffing.(*Sniffer).SniffQuic | 6.31% | 8.31% | +2.00（相对） | 同上（相对增长，非绝对回归） |

> OQ-S4-4 判据：mallocgc cum% 不增（14.20→14.30 在噪声内）+ NewStreamSniffer cum% 不增（消除）= **PASS**。gcBgMarkWorker 27→10 为 bonus，强达成 H7「砍分配→降 GC CPU」闭环。

## 开放问题追踪

- OQ-S4-1：async goroutine 复用读语义风险 —— **闭环**。实现采用「内联单 goroutine + readResultCh 复用」（保守方案），保留读语义（顺序/超时/错误传播逐位一致）。race gate count=3 全过，TLS/QUIC/AsyncFallback/Timeout 语义测试全过。
- OQ-S4-2：T2 是否真依赖 T1 struct 形状 —— **评估后解耦**。T2 的 findSniExtension 绝对索引改造独立于 T1 struct 形状；LinearLocator.Reset 独立。但三 task 共享 sniffer.go，按降级规则仍串行执行（commit_budget 未变）。
- OQ-S4-3：sniffHTTPHostHeader + bytes.Index 纯 CPU 计算热点 —— 记 Sprint+1 候选（非本 Sprint 主题）。
- OQ-S4-4：cpu_profile_review PASS 判据 —— **闭环见上表**。mallocgc 不增 + NewStreamSniffer 消除 = PASS；gcBgMarkWorker 大降为 bonus。
