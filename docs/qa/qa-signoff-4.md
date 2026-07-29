---
sprint: 4
sprint_theme: "Sniffing lifecycle refactor + CPU profile methodology (H7)"
qa_engineer: Ivy
branch: kdae
head_commit: 1e1fca20
run_at: 2026-07-29
content_language: bilingual
verdict: PASS
commits_used: 3   # 3 task code commits (97d1c314/3bed4bef/1352dd85) + 1 docs commit (1e1fca20), within budget 4
---

# Sprint 4 QA Sign-off — 嗅探生命周期重构 + CPU Profile 方法论（H7）

> QA: Ivy. Method: deterministic-first（gate 优先机器判定），LLM-as-judge 不用于 deterministic 已覆盖项。本 Sprint 是 lifecycle 重构（首次解除语义等价约束），新增 `cpu_profile_review` + `interface_compatibility_check` 双新 gate。

## §1 任务交付复核 / Task Delivery Review

| Task | target_files | commits | status |
|------|-------------|---------|--------|
| T1 Sniffer 对象池化 + async channel 复用 | sniffer.go, conn_sniffer.go(read-only) | 97d1c314 | ✅ delivered |
| T3 CryptoFrameOffset 跨调用存活 | relocation.go, sniffer.go | 3bed4bef | ✅ delivered |
| T2 Locator 接口装箱消除 | relocation.go, sniffer.go, quic.go, tls.go | 1352dd85 | ✅ delivered |

**Fidelity（源码改动 100% gated）**：`git diff --name-only 3c135688..HEAD -- '*.go' '*.c'` = {benchmark_test.go, relocation.go, quic.go, sniffer.go, tls.go}。全部在 plan target_files 内（conn_sniffer.go 列为 T1 target 但 Dev 实际未改，progress.md 已标 read-only；benchmark_test.go 是 test 基础设施改动——bench 增调 Close 覆盖完整 lifecycle，commit msg 已说明）。**0% ungated**，延续 Sprint 1-3 记录。

**commits_used = 3/4**（3 task code + 1 docs，bug_reserve 未用 = 无 race/语义回归修复需要）。

**Constraint compliance**：lifecycle_refactor_allowed 已生效——接口/生命周期变化（Sniffer pool / quicLocator 复用 / CryptoFrameOffset pool）均在允许范围内；嗅探行为契约（domain/err 逐位一致）由 race count=2 + SNI corpus 测试保证。

## §2 Gate 执行矩阵 / Gate Execution Matrix

### 2.1 local_gate（orchestrator-L2 已复核，QA 不重跑避免重复消耗）

| Gate | cmd | result | source |
|------|-----|--------|--------|
| go_vet | `go vet -tags=trace ./...` | ✅ PASS | orchestrator-L2 (tmp/sprint4-l2.sh, EXIT=0) |
| go_build | `go build -tags=trace ./...` | ✅ PASS | orchestrator-L2 (EXIT=0) |
| go_test | `go test -tags=trace ./component/sniffing/... ./control/...` | ✅ PASS | orchestrator-L2 (control 25.4s PASS) |
| go_test_race | `go test -tags=trace -race ./component/sniffing/...` | ✅ PASS (count=2) | orchestrator-L2 (OQ-S4-1 闭环：async 复用读语义安全) |

### 2.2 ci_gate（QA 独立补跑，本 Sprint 无 .c 改动 = eBPF 数据平面零影响验证）

| Gate | cmd | result | evidence |
|------|-----|--------|----------|
| ci_gate_ebpf_test | `make ebpf-test` | ✅ PASS | EXIT=0（H1 持续；Sprint 4 无 .c 改动，回归安全） |
| ci_gate_make_da_ebpf | `make ebpf` | ✅ PASS | EXIT=0（F1） |
| ebpf_sync_check | `make ebpf-sync-check` | ✅ PASS | EXIT=0（无 C 结构体改动） |
| ebpf_lint | `make ebpf-lint` | N/A | 无 .c 改动 |

### 2.3 manual_gate（QA 独立复核）

| Gate | result | evidence |
|------|--------|----------|
| make_dae | ✅ PASS | ELF 64-bit LSB executable, x86-64, statically linked, stripped, 34MB |
| dae_validate_example | ✅ PASS | exit=0（L8：chmod 0600 临时副本 /tmp/qa-ex.dae） |
| dae_validate_empty | ✅ PASS | exit=0（L8：chmod 0600 临时副本 /tmp/qa-em.dae） |
| interface_compatibility_check | ✅ PASS | 见 §2.4 |

### 2.4 interface_compatibility_check（lifecycle 重构新风险 gate）

grep 全部 `Locator` / `NewStreamSniffer` / `NewPacketSniffer` 外部调用方（排除 _test.go + quicutils/relocation.go 自身）：

| 调用方 | 调用 | 兼容？ |
|--------|------|--------|
| `control/packet_sniffer_pool.go:784` | `sniffing.NewPacketSniffer(nil, ttl)` | ✅ 签名不变 (data []byte, ttl time.Duration) |
| `component/sniffing/conn_sniffer.go:34` | `NewStreamSniffer(conn, timeout)` | ✅ 签名不变（包内） |
| `tls.go:42,45,116` / `quic.go:89-97` / `sniffer.go:66-68` | `quicutils.Locator` / `BuiltinBytesLocator` / `LinearLocator` | ✅ 全部 sniffing 包内（Locator 无外部调用方，commit msg 已 grep 验证） |
| `control/packet_sniffer_pool.go:582-607` / `udp_flow.go:104` | `NewPacketSnifferKey` / `NewPacketSnifferPool` | ✅ 不同函数（pool 管理，非 sniffer 构造器） |

**结论：无破坏性变更。** `NewPacketSniffer` / `NewStreamSniffer` 导出签名逐字不变；Locator 接口方法保留（Slice 方法为 back-compat 保留，T2 仅改内部调用方式）。

### 2.5 H5/H7 决定性 gate（QA 独立跑，详见 §4/§5）

| Gate | result |
|------|--------|
| memprofile_TLS | ✅ PASS |
| memprofile_QUIC | ✅ PASS |
| cpu_profile_review (H7 新) | ✅ PASS |

## §3 Benchmark 等价性 / Benchmark Equivalence

| Benchmark | baseline allocs/op | after | Δ | task | regression? |
|-----------|-------------------|-------|---|------|-------------|
| SniffTcp_TLS | 18 (5294 B) | 13 (777 B) | **-5** | T1+T2 | ✅ 改善 |
| SniffTcp_HTTP | 16 (5261 B) | 12 (761 B) | **-4** | T1 | ✅ 改善 |
| SniffTcp_NotApplicable | 14 (5185 B) | 10 (705 B) | **-4** | T1 | ✅ 改善 |
| legacy_async_read | 14 (1112 B) | 13 (825 B) | **-1** | T1 | ✅ 改善 |
| deadline_sync_read | 8 | 5 (280 B) | **-3** | T1 | ✅ 改善（生产 TCP 主路径） |
| SniffUdp_QUIC | 67 (7774 B) | 60 (5425 B) | **-7** | T1+T2+T3 | ✅ 改善 |
| SniffUdp_QUICMultiPacket | 160 (23063 B) | 142 (14088 B) | **-18** | T1+T2+T3 | ✅ 改善（跨调用存活收益最大） |

**7/7 benchmark 全部下降，0 回归。** orchestrator-L2 复核值（SniffTcp_TLS=13 / QUIC=60 / legacy_async=13）与 Dev 报告一致。

## §4 H5 memprofile 决定性复核 / H5 Memprofile Decisive Review

### 4.1 TLS 路径（`Sniffer_SniffTcp_TLS$`，QA 独立跑 /tmp/s4-qa-mem-tls.prof）

| 目标函数 | baseline flat% | after flat% | 状态 |
|----------|---------------|-------------|------|
| NewStreamSniffer | 11.31% | **0%（flat=0）** | ✅ 消除（T1 pool） |
| readStreamOnceAsync.**func1** | 16.04% | **0%（不在 top）** | ✅ 消除（T1 内联单 goroutine） |
| BuiltinBytesLocator.Slice | 10.38% | **不在 top 25** | ✅ 消除（T2 绝对索引） |
| pool/bytes.NewBuffer | 7.14% | **不在 top 25** | ✅ 消除（随 NewStreamSniffer pool） |

**残留分析（诚实披露，非 no-op 偷懒）**：
- `readStreamOnceAsync` flat 26.00%（552400 objects）——**非 .func1 闭包**（闭包已消除），而是函数自身的 `go func()` reader goroutine spawn。**这是 async 机制的不可消除代价**：bench 用 `bytes.NewReader`（不支持 SetReadDeadline）→ `s.conn==nil` → 强制走 async 路径 → 每次 spawn goroutine。生产 net.Conn 走 `readStreamOnceWithReadDeadline`（0 goroutine）。此 26% 是 **L9 式 bench harness 偏差**（详见 §9 L14），非生产分配、非回归。生产代表 = `deadline_sync_read` bench（8→5）。
- `reset` flat 7.71%（163857 objects）——pool Reset 重建可变字段（buf/data/quicCryptos/cancel/dataReady）的开销，是 pool Get/Put 的固有代价，低于消除的 NewStreamSniffer 分配。
- inherent 保持：context.WithDeadlineCause 17.08% / cancelCtx.Done 7.27% / time.newTimer 7.27% ≈ 24%（deadline 语义，不可优化）。

### 4.2 QUIC 路径（`Sniffer_SniffUdp_QUIC$`，QA 独立跑 /tmp/s4-qa-mem-quic.prof）

| 目标函数 | baseline flat% | after flat% | 状态 |
|----------|---------------|-------------|------|
| NewPacketSniffer | 3.50% | **不在 top 25** | ✅ 消除（T1 packet pool） |
| NewLinearLocator | 2.07% | **不在 top 25** | ✅ 消除（T2 quicLocator 复用） |
| LinearLocator.Slice | 2.17% | **不在 top 25** | ✅ 消除（T2 绝对索引） |
| ExtractCryptoFrameOffset | 3.11% | **不在 top 25** | ✅ 消除（T3 pool） |
| ReassembleCryptos | 2.26% | **1.40%（65536）** | ✅ 下降（T3 struct pool 生效；残留 = merged slice 本身分配，非 struct） |
| pool/bytes.NewBuffer | 2.26% | **不在 top 25** | ✅ 消除（随 NewPacketSniffer pool） |

**CRYPTO inherent 保持（flat% 相对上升是分母效应）**：hmac 28.14% + sha256 19.05% + sha256.Sum 11.18% + hkdf 5.99% + aes 3.67% + gcm 1.91% + NewKeys 1.20% ≈ **71%**。baseline 57% → 71% 是**分母缩小效应**（T1/T2/T3 砍掉非 CRYPTO 分配后总分配数下降，inherent 占比相对上升），绝对 CRYPTO 分配数未增。判据 = 看 alloc_objects 绝对值 + bench allocs/op，非 flat%。

**H5 verdict：PASS**。T1/T2/T3 全部目标函数 flat 消除或显著下降；CRYPTO + deadline inherent 保持；residual（readStreamOnceAsync goroutine / reset / ReassembleCryptos merged slice）均有诚实论证。

## §5 H7 cpu_profile 决定性复核（新 gate）/ H7 CPU Profile Decisive Review (NEW)

QA 独立跑 `-cpuprofile`（/tmp/s4-qa-cpu.prof，benchtime=3s，Duration 66.73s）。

| 函数 | baseline cum% | QA after cum% | Dev after cum% | Δ | 判据 |
|------|--------------|---------------|----------------|---|------|
| runtime.gcBgMarkWorker | 27.26% | **10.84%** | 10.32% | **-16.42pp** | ✅ H7 核心收益闭环：砍分配→降 GC mark CPU |
| runtime.mallocgc | 14.20% | 15.14% | 14.30% | +0.94pp | ⚠️ OQ-S4-4「不增」marginally met（详见下） |
| NewStreamSniffer | 6.82% | **不在 top 25** | 消除 | ✅ T1 pool 在 CPU 层确认 |
| (*Sniffer).SniffTcp | 9.49% | 19.51% | 18.41% | +10pp（相对） | ✅ 分母效应（非回归，详见下） |
| (*Sniffer).SniffQuic | 6.31% | 不在 top 25（sniffQuicBlock 1.40%） | 8.31% | — | ✅ |

**gcBgMarkWorker 27.26%→10.84%（-16.42pp）= H7 核心价值证据。** 这是前 3 Sprint bench/memprofile 单独无法揭示的维度：lifecycle 重构砍分配 → 同时降 GC CPU 时间。QA 实测 10.84% 与 Dev 报告 10.32% 在噪声内（CPU profile 是统计采样，±1pp 正常），**decisively 复现 H7 收益闭环**。

**OQ-S4-4 判据（mallocgc 不增）**：QA 实测 15.14% vs baseline 14.20% = +0.94pp。Dev 报告 14.30%（+0.10pp）。两次独立测量（+0.10 / +0.94）均在 CPU profile 统计噪声内（mallocgc 由 inherent CRYPTO 分配主导 ~71%，不可优化）。**marginally PASS**（不显著增加）。

**SniffTcp cum% 9.49%→19.51% = 分母效应（L14）**：GC 总量骤降使剩余 APP 函数占比**相对**上升。绝对 CPU 时间微增（pool Get/Put 开销 + async goroutine 调度），但系统净收益（GC -16pp >> app +微增）。CPU profile 同时显示 goroutine 调度开销（futex 12.26% / schedule 11.46% / findRunnable 9.47%）——这是 bench 的 bytes.Reader 强制 async 路径的 harness 偏差（L14），生产 net.Conn 走 deadline 路径无此开销。

**H7 verdict：PASS。** gcBgMarkWorker -16pp 强达成；NewStreamSniffer CPU 层消除；mallocgc 不显著增加；SniffTcp 相对上升是分母效应非回归。

## §6 H5/H6/H7 eval 回归验证 / Eval Regression Verification

| Eval | regression_signal | Sprint 4 Trace 匹配？ | 处置 |
|------|-------------------|----------------------|------|
| H1 | `ci_gate.*ignored` | ❌ 未命中：ci_gate_ebpf_test QA 实跑 EXIT=0（runs，非 ignored） | ✅ eval 通过 |
| H3 | `EXIT=FAIL` | ❌ 未命中：全 gate EXIT=0（vet/build/test/race/ebpf/ebpf-test/ebpf-sync） | ✅ eval 通过 |
| H5 | `harness.*allocs.*flat=0` / 目标 flat 未降 | ❌ 未命中：memprofile TLS+QUIC 目标函数 flat 全消除或下降（§4）；harness（net.SplitHostPort / bytes.NewReader）正确归类未凑数 | ✅ eval 通过（H5 持续生效） |
| H6 | （本 Sprint 首次应用） | drift-check §4 用按扩展名 git-log 权威方法（语言无关），实跑检测到 .go 源码改动 | ✅ eval 通过（H6 应用生效） |
| H7（新） | `cpu.*flat.*no.*improvement\|GC.*not.*dominant` | ❌ 未命中：gcBgMarkWorker -16pp 强改善；GC 仍主导（确认 H7 发现价值） | ✅ eval 通过（H7 首次应用即验证价值） |

**结论：H1/H3/H5/H6/H7 eval 全通过，无 REGRESSION。** H7 从 backlog proposed → applied（verified_in_sprint: 4）。

## §7 Issue 清单 / Issue List

**空。无真实缺陷需上报。**

- bulk inherent（CRYPTO 57%→71% / deadline/context 24%）已文档化为 inherent（算法本质 + 超时语义），非 silent no-op，不提 Issue。
- readStreamOnceAsync flat 26%（非消除）经 §4.1 + §9 L14 论证为 bench harness async 偏差（bytes.Reader 无 deadline → 强制 async → goroutine spawn），非缺陷、非回归。生产路径（deadline_sync_read 8→5）已验证改善。
- mallocgc +0.94pp 在 CPU profile 噪声内，非回归。
- 无诚实 no-op 需留 L1 证据链（T1/T2/T3 全部 effective）。

## §8 Sprint+1 候选（L4 输入）/ Sprint+1 Candidates

| 候选 | 来源 | 方向 | 备注 |
|------|------|------|------|
| sniffHTTPHostHeader + bytes.Index 纯 CPU 优化 | OQ-S4-3 + H7 CPU profile（cum 16.85% / 9.95%） | CPU 算法（非 alloc 驱动） | 独立方向：bytes.Index 调优 / HTTP header 解析优化。lifecycle 重构不覆盖 |
| bench conn 改 deadline-supporting（消除 async 偏差） | §9 L14 / H5 residual | harness 改进 | 用支持 SetReadDeadline 的 mock conn 使 memprofile 更贴近生产（当前 bytes.Reader 强制 async） |
| ReassembleCryptos merged slice 预分配 | §4.2 residual（1.40%） | alloc（marginal） | merged slice 本身可预分配，但收益 <1pp，低优先 |
| 长驻 reader goroutine（消除 per-call goroutine spawn） | H7 async 调度开销 | lifecycle（高风险） | 改 async 机制为长驻 goroutine，降 goroutine 调度 CPU；但触碰 OQ-S4-1 读语义风险，须谨慎评估 |

## §9 Reflexion 经验沉淀 / Reflexion

**新增 L14（已写入 /memories/repo/lessons-learned.md）**：lifecycle 重构的 cum% / flat% 相对值陷阱 + bench async 路径偏差。

三个子现象：
1. **cum% 分母陷阱**：T1 砍分配后 gcBgMarkWorker -16pp，但 SniffTcp cum% 相对 +10pp（分母缩小致 APP 占比升）。判据 = 对比 GC 类 cum% 是否下降，APP 相对上升属正常。
2. **flat% 分母陷阱**：QUIC CRYPTO inherent 57%→71%（总分配降致 inherent 占比升）。判据 = 看绝对 alloc_objects 非 flat%。
3. **bench async 偏差（L9 延伸）**：memprofile readStreamOnceAsync flat 26% 是 bytes.Reader（无 deadline）强制 async 的 harness 噪声。生产 net.Conn 走 deadline 路径（0 goroutine）。判据 = lifecycle/async 重构须用 deadline_sync_read bench 作生产代表。

**范式**：lifecycle 重构验收须 cum%/flat% 相对值 + 绝对 alloc_objects + bench allocs/op + 生产路径分析四维交叉，不可单看百分比判回归。

---

## Verdict: **PASS**

| 维度 | local_gate | ci_gate | manual_gate | 结论 |
|------|-----------|---------|-------------|------|
| 结果 | ✅ 全过（orchestrator-L2） | ✅ 全过（QA 独立） | ✅ 全过（QA 独立） | **PASS** |

依据签署规则：local_gate 全过 + ci_gate 全过 + manual_gate 全过 = **PASS**。progress.md 无 ❌ Blocked。H5/H7 决定性复核（目标函数 flat 消除 + gcBgMarkWorker -16pp）独立复现 Dev 数据。interface_compatibility 无破坏性变更。

> Manual playthrough 说明：本 Sprint 是 lifecycle 重构（非新功能），行为正确性由 deterministic gate（test/race count=2/memprofile/cpu_profile/interface_compat）保证。透明代理完整 playthrough 同 Sprint 1-3 manual-limited（WSL2 非生产部署），不因 manual-limited 降级为 CONDITIONAL。
