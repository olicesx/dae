---
sprint: 4
sprint_theme: "Sniffing lifecycle refactor + CPU profile methodology (H7) / 嗅探生命周期重构 + CPU profile 方法论"
phase: planning
owner: Remy
branch: kdae
created: 2026-07-29
content_language: bilingual
prev_sprint: 3
drift_check: docs/sprint-4/drift-check.md
constraint_policy: lifecycle_refactor_allowed
h5_applied: true
h6_applied: true
h7_applied: true   # 首次引入 CPU profile 维度

# === blast_radius（plan 锁定，执行期不得超）===
blast_radius:
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true
  hard_cap: 10
  commit_budget: 4
  commit_budget_formula: dag_layers + strong_coupling_count + bug_reserve
  commit_budget_derivation: "dag_layers=2（layer1: T1,T3 并行 / layer2: T2 依赖 T1）+ strong_coupling=1（T2 接口收敛触碰 T1 池化后的 Sniffer struct 形状）+ bug_reserve=1 = 4"
  commit_budget_risk_note: >
    4 = 3 task code commits + 1 buffer（race/语义回归修复或 docs/progress）。
    lifecycle 重构改变接口/生命周期，race + interface_compatibility 风险高于前 3 Sprint，
    bug_reserve=1 是必要的弹性。T2 串行在 T1 之后（接口依赖），不会并发爆 commit。

# === task_sizing ===
task_sizing:
  task_count: 3
  strong_coupling_count: 1
  dag_layers: 2
  topology: hybrid
  topology_rationale: "T1（对象池化）与 T3（跨调用存活）独立，layer1 并行；T2（接口收敛）依赖 T1 建立的 Sniffer struct 形状（Locator 可能内嵌），layer2 串行。hybrid = 并行 + 串行混合。"

# === task DAG（每 task 标注 CPU profile + memprofile 双证据）===
tasks:
  T1:
    name: "Sniffer 对象池化：NewStreamSniffer / NewPacketSniffer struct + readStreamOnceAsync goroutine/channel 复用"
    source: "H7 CPU profile（NewStreamSniffer cum 6.82% / SniffTcp cum 9.49% / SniffQuic cum 6.31%；GC 主导 41-50%）+ H5 memprofile（NewStreamSniffer flat 11.31% + readStreamOnceAsync.func1 flat 16.04% + NewPacketSniffer flat 3.50% + pool.Put 17.71%）"
    target_files:
      - "component/sniffing/sniffer.go"           # NewStreamSniffer / NewPacketSniffer / readStreamOnceAsync
      - "component/sniffing/conn_sniffer.go"      # Sniffer 生命周期所有者（ConnSniffer）
    target_sites:
      - "NewStreamSniffer @48（每连接构造 Sniffer struct + pool.GetBuffer + chan dataReady）"
      - "NewPacketSniffer @62（每包构造 Sniffer struct + buf）"
      - "readStreamOnceAsync @140（async 路径每调用 spawn goroutine + make(chan readResult,1)）"
      - "ensureAsyncContext @78（context.WithDeadline 每连接）"
    liveness_gate: "G1 PASS：NewStreamSniffer←conn_sniffer.go:34（生产 ConnSniffer 构造）；readStreamOnceAsync←readStreamOnce←SniffTcp sniff loop；NewPacketSniffer←UDP 包嗅探生产路径。全 LIVE，非 test-only"
    heat_gate: "G2 PASS：sniffing 每连接/每包触发 = warm/hot，高 ROI"
    memprofile_evidence:
      SniffTcp_TLS: "NewStreamSniffer flat 11.31% + readStreamOnceAsync.func1 flat 16.04% + pool/bytes.NewBuffer 7.14%"
      SniffUdp_QUIC: "NewPacketSniffer flat 3.50% + pool.Put 17.71% + pool/bytes.NewBuffer 2.26%"
    cpu_profile_evidence:
      cum: "NewStreamSniffer cum 6.82% / SniffTcp cum 9.49% / SniffQuic cum 6.31%"
      insight: "GC 主导 41-50% CPU（mallocgc 14.20% + gcBgMarkWorker 27.26%）；砍 Sniffer 分配 → 同时降 CPU GC 时间"
    depends_on: []
    bench_coverage: yes
    bench_baseline: {SniffTcp_TLS: "18 allocs/op 5294B", SniffTcp_HTTP: "16 allocs/op 5261B", SniffUdp_QUIC: "67 allocs/op 7774B", SniffTcp_NotApplicable: "14 allocs/op", SniffTcpReadStrategy_legacy_async_read: "14 allocs/op"}
    pool_reuse: "新增 sync.Pool[*Sniffer]（Reset 清理 buf/sniffed/data/quicCryptos 等）+ async goroutine/channel 复用（per-Sniffer 复用而非每 readStreamOnceAsync 新建）"
    safety_condition: "语义：池化 Sniffer 须在 Close/用尽后 Put 且 Reset 清零所有字段（buf Reset、data/quicCryptos nil、sniffed 空、cancel 调用），避免跨连接数据污染；readStreamOnceAsync 的 goroutine 复用须保证读语义（顺序/超时）与现有一致——race gate + 语义对照测试必跑"
    expected: effective_medium
    noop_risk: "低：NewStreamSniffer 11.31% + async.func1 16.04% flat>0 是真实生产分配（G4 通过）；但 async goroutine 复用若设计不当可能引入读顺序问题 → race gate 把关"
  T2:
    name: "Locator 接口收敛：BuiltinBytesLocator / LinearLocator 装箱分配消除"
    source: "H5 memprofile（BuiltinBytesLocator.Slice flat 10.38% TLS / NewLinearLocator flat 2.07% + LinearLocator.Slice flat 2.17% QUIC）"
    target_files:
      - "component/sniffing/internal/quicutils/relocation.go"   # Locator interface / LinearLocator / NewLinearLocator
      - "component/sniffing/sniffer.go"                          # 调用方（若接口形状随 T1 改变）
      - "component/sniffing/quic.go"                             # NewLinearLocator(s.quicCryptos) 调用点
      - "component/sniffing/tls.go"                              # BuiltinBytesLocator 调用点
    target_sites:
      - "Locator interface @quicutils（Range/Slice/At/Len/Bytes）"
      - "NewLinearLocator @154（返回 *LinearLocator，调用方装箱入 Locator 接口）"
      - "BuiltinBytesLocator.Slice（TLS 路径，每 Slice 装箱新 Locator）"
    liveness_gate: "G1 PASS：NewLinearLocator←quic.go:89（生产 SniffQuic）；LinearLocator/BuiltinBytesLocator 经 SniffTls/SniffQuic 生产路径调用。全 LIVE"
    heat_gate: "G2 PASS：每 TLS/QUIC 嗅探触发 = warm"
    memprofile_evidence:
      SniffTcp_TLS: "BuiltinBytesLocator.Slice flat 10.38%"
      SniffUdp_QUIC: "NewLinearLocator flat 2.07% + LinearLocator.Slice flat 2.17%"
    cpu_profile_evidence:
      cum: "含于 SniffTcp 9.49% / SniffQuic 6.31%（Locator 操作非 CPU 主项，但装箱触发 GC）"
    depends_on: [T1]
    depends_on_rationale: "T2 可能内嵌 Locator 字段到池化后的 Sniffer struct（T1 决定 struct 形状），故串行在 T1 后；若评估后 T2 独立于 T1 struct 形状，Dev 可提请解耦降为并行（OQ-S4-2）"
    bench_coverage: yes
    bench_baseline: {SniffTcp_TLS: "18 allocs/op", SniffUdp_QUIC: "67 allocs/op"}
    pool_reuse: "减少接口装箱（泛型/值类型/预分配 Locator 槽位），而非新增 Pool"
    safety_condition: "interface_compatibility_check：Locator 是 quicutils 包导出接口，须 grep 所有外部调用方确保新形状不破坏；语义：Range/Slice/At/Len/Bytes 返回值逐位一致"
    expected: effective_small
    noop_risk: "中：Locator 装箱占比中等（TLS 10.38% / QUIC 4.24%），有效但幅度小于 T1"
  T3:
    name: "CryptoFrameOffset 跨调用存活：ExtractCryptoFrameOffset / ReassembleCryptos 经 s.quicCryptos 复用"
    source: "H5 memprofile（ExtractCryptoFrameOffset flat 3.11% + ReassembleCryptos flat 2.26% QUIC）"
    target_files:
      - "component/sniffing/internal/quicutils/relocation.go"   # ExtractCryptoFrameOffset / ReassembleCryptos / CryptoFrameOffset
      - "component/sniffing/sniffer.go"                          # s.quicCryptos 字段（跨包嗅探存活载体）
    target_sites:
      - "ExtractCryptoFrameOffset @89（每帧 &CryptoFrameOffset{}）"
      - "ReassembleCryptos @24（merged := make([]*CryptoFrameOffset,...) + 每 merge &CryptoFrameOffset{}）"
      - "s.quicCryptos @sniffer.go（跨 readStreamOnce 调用存活，累积 crypto frames）"
    liveness_gate: "G1 PASS：ExtractCryptoFrameOffset←ReassembleCryptos←sniffQuicBlock←SniffQuic（生产 UDP 嗅探）。LIVE"
    heat_gate: "G2 PASS：每 QUIC crypto frame 触发 = warm"
    memprofile_evidence:
      SniffUdp_QUIC: "ExtractCryptoFrameOffset flat 3.11% + ReassembleCryptos flat 2.26%"
    cpu_profile_evidence:
      cum: "含于 SniffQuic 6.31%（crypto frame 解析非 CPU 主项）"
    depends_on: []
    bench_coverage: yes
    bench_baseline: {SniffUdp_QUIC: "67 allocs/op", SniffUdp_QUICMultiPacket: "160 allocs/op"}
    pool_reuse: "CryptoFrameOffset 经 s.quicCryptos 跨调用累积复用（避免每帧新 struct）；ReassembleCryptos merged slice 预分配/复用"
    safety_condition: "语义：crypto frame 偏移合并结果与现有逐位一致（合并/排序/overlap 处理不变）；s.quicCryptos 跨包累积须保证 sniffer 生命周期内不泄漏（Reset 清理）"
    expected: effective_small
    noop_risk: "低：ExtractCryptoFrameOffset flat 3.11% 真实（G4 通过）；多包 QUIC（160 allocs/op）场景收益更明显"

# === verifiable_gates ===
gates:
  go_vet:        {cmd: "go vet -tags=$(cat .build_tags) ./...", target: clean}
  go_build:      {cmd: "go build -tags=$(cat .build_tags) ./...", target: ok}
  go_test:       {cmd: "go test -tags=$(cat .build_tags) ./component/sniffing/... ./control/...", target: pass}
  go_test_race:  {cmd: "go test -tags=$(cat .build_tags) -race ./component/sniffing/...", target: pass, reason: "T1 池化 + async goroutine 复用 + T3 跨调用存活均涉及并发；race 必跑（lifecycle 重构最高风险项）"}
  benchmark_no_regression:
    cmd: "go test -tags=$(cat .build_tags) -bench='Sniff' -benchmem -run='^$' -benchtime=300ms ./component/sniffing/"
    target: "allocs/op 不增；T1（Sniffer/async 池化）命中则 SniffTcp_TLS/HTTP/NotApplicable + async_read 显著降；T3 命中则 QUIC/QUICMultiPacket 降"
  memprofile_review:
    cmd: "go test -tags=$(cat .build_tags) -bench='Sniffer_SniffTcp_TLS$|Sniffer_SniffUdp_QUIC$' -memprofile=/tmp/s4-after.mem -run='^$' -benchtime=300ms ./component/sniffing/ && go tool pprof -top -sample_index=alloc_objects -nodecount=20 /tmp/s4-after.mem"
    target: "NewStreamSniffer / readStreamOnceAsync.func1（T1）/ BuiltinBytesLocator.Slice / NewLinearLocator（T2）/ ExtractCryptoFrameOffset / ReassembleCryptos（T3）flat 下降或归零；CRYPTO inherent（hmac/sha256/hkdf）flat 保持"
    reason: "H5：memprofile 复核是 lifecycle 重构的决定性验证（确认 flat 下降而非 bench 噪声）"
  cpu_profile_review:
    cmd: "go test -tags=$(cat .build_tags) -bench=. -cpuprofile=/tmp/s4-cpu-after.prof -run='^$' -benchtime=3s ./component/sniffing/ && go tool pprof -top -cum -nodecount=20 /tmp/s4-cpu-after.prof"
    target: "runtime.mallocgc + gcBgMarkWorker cum% 下降（验证砍分配 → 降 GC CPU 的 H7 收益闭环）；NewStreamSniffer/SniffTcp/SniffQuic cum% 不增"
    reason: "H7（新 gate）：CPU profile 首次作为验证维度。本 Sprint 调研发现 GC 主导 41-50% CPU，lifecycle 重构应同时降 GC CPU 时间——此 gate 量化该收益"
  interface_compatibility_check:
    cmd: "grep -rn 'Locator' --include='*.go' . | grep -v '_test.go' | grep -v 'quicutils/relocation.go' && grep -rn 'NewStreamSniffer\\|NewPacketSniffer' --include='*.go' . | grep -v '_test.go'"
    target: "所有 Locator / NewStreamSniffer / NewPacketSniffer 外部调用方不破坏（签名兼容）；若 T1/T2 改了导出签名，须逐一更新调用方"
    reason: "lifecycle 重构改变接口/生命周期，interface_compatibility 是前 3 Sprint（语义等价）没有的新风险 gate"
  ci_gate_ebpf_test: {cmd: "make ebpf-test", local: runs, note: "H1 持续；T1/T2/T3 无 .c 改动，回归安全"}
  ci_gate_make_da_ebpf: {cmd: "make ebpf", local: runs}
  ebpf_lint: {cmd: "make ebpf-lint", target: na, note: "无 .c 改动"}
  ebpf_sync_check: {cmd: "make ebpf-sync-check", target: pass, note: "无 C 结构体改动"}
  no_behavior_change: {target: "config/CLI/API 错误码不变；嗅探结果（domain/err）在所有输入下与改前逐位一致；仅生命周期/分配方式变化（constraint_policy: lifecycle_refactor_allowed 允许接口/生命周期变化，但嗅探行为契约不变）"}

# === H5/H7 eval 回归验证（drift-check §5 要求显式写出）===
eval_regression_verification:
  H7: >
    本 Sprint = H7 首次应用。验证方式：Producer 阶段已跑 CPU profile（runtime-context.md §H7）。
    H7 生效证据 = cpu_profile_review gate 量化「砍分配 → 降 GC CPU」的收益闭环（本 Sprint 调研
    发现 GC 主导 41-50% CPU，是 bench/memprofile 单独无法揭示的维度）。Sprint 结束统计：
    runtime.mallocgc + gcBgMarkWorker cum% 应随 Sniffer 分配下降而下降。
  H5: "延续 Sprint 3。memprofile_review gate 复核 T1/T2/T3 各 flat 下降；CRYPTO inherent 保持（harness/inherent 不得凑数）"
  H6: "本 Sprint 应用：drift-check §4 用按扩展名 git-log 权威方法（语言无关），backlog 标 applied"
  H1: "ci_gate_ebpf_test.local = runs（延续），无 ignored 回归"
  H3: "全程 tmp/*.sh（sprint4-survey.sh），gate exit 可靠"
---

# Sprint 4 Plan — 嗅探生命周期重构 + CPU Profile 方法论（H7）

> 首次解除「语义等价」约束（constraint_policy: lifecycle_refactor_allowed），把 Sprint 1-3 三次 deferred 的 sniffing lifecycle-boundary 候选纳入。**核心新增 = H7 CPU profile 方法论**：Producer 阶段跑 CPU profile 揭示「GC 主导 CPU（41-50%）→ alloc 与 CPU 热点收敛」，为 lifecycle 重构提供第三维证据。
> 输入：[drift-check.md](drift-check.md) + [runtime-context.md](runtime-context.md) §H7 CPU + §H5 mem + Sprint 2/3 hill-climbing（lifecycle 强信号）。

## 1. 目标 / Goals

- **T1（对象池化，TCP+UDP 双路径）**：`NewStreamSniffer`/`NewPacketSniffer` Sniffer struct + `readStreamOnceAsync` goroutine/channel 复用（mem flat 11.31%+16.04%+3.50%+17.71%；CPU cum 6.82%+9.49%+6.31%）。
- **T2（接口收敛，依赖 T1）**：`BuiltinBytesLocator`/`LinearLocator` 装箱入 `Locator` 接口的分配消除（mem flat TLS 10.38% / QUIC 4.24%）。
- **T3（跨调用存活，UDP）**：`ExtractCryptoFrameOffset`/`ReassembleCryptos` 的 `CryptoFrameOffset` 经 `s.quicCryptos` 跨调用复用（mem flat 3.11%+2.26%）。
- **方法论**：应用 H7（CPU profile 新维度）+ 延续 H5（memprofile）；新增 `cpu_profile_review` + `interface_compatibility_check` 两个 gate。

## 2. 非目标 / Out-of-Scope（本 Sprint 不做什么）

- ❌ CRYPTO inherent（hmac 21.95% / sha256 22.47% / hkdf 6.30% / aes 2.88% ≈ 57%）—— 算法本质，不可优化。
- ❌ deadline/context/timer inherent（context.WithDeadlineCause 11.82% + time.newTimer 8.35% + cancelCtx 3.62% ≈ 24% TLS）—— 超时语义，消除即破坏行为。
- ❌ 测试瘦身 / 批量删测试。
- ❌ 新协议 / 新 feature。
- ❌ 行为/API/config 变更（嗅探结果 domain/err 逐位一致；仅生命周期/分配方式变）。
- ❌ vendor / vmlinux-*.h / fork（quic-go、outbound）。
- ❌ eBPF C（tproxy.c，Sprint 1 B1/B2 已证无真冗余）。
- ❌ net.SplitHostPort.func1（5.84%）—— harness（bench 构造地址），非生产。
- ❌ 冷路径（CloneCacheForReload）、test-only 函数（L2）。
- ⚠️ **注意**：Sprint 1 的「锁合并/重排、巨型文件拆分」Non-Goals 已**被本 Sprint 主题覆盖**（lifecycle 重构含接口/生命周期调整），不再作为硬 Non-Goal；但本 Sprint 仍不主动做无关的巨型文件物理拆分。

## 3. 任务 DAG / Task DAG

```
layer1:  T1 (对象池化) ─────┐          T3 (跨调用存活) ──┐
          │                  │                            │
          └──> layer2: T2 (接口收敛, depends T1)          │
                                                           │
全部完成后 → gate（含 cpu_profile_review + interface_compatibility_check）
```

| 任务 | target_files | mem flat%（CPU cum%） | 期望 | 依赖 |
|------|-------------|----------------------|------|------|
| T1 | sniffer.go, conn_sniffer.go | 11.31+16.04+3.50+17.71（6.82+9.49+6.31） | effective_medium | — |
| T2 | relocation.go, sniffer.go, quic.go, tls.go | 10.38+2.07+2.17（含于 SniffTcp/Quic） | effective_small | T1 |
| T3 | relocation.go, sniffer.go | 3.11+2.26（含于 SniffQuic） | effective_small | — |

## 4. H7+H5 分类汇总（决策依据，详见 runtime-context.md）

| 候选 | mem flat% | CPU cum% | H5/H7 结论 | 处置 |
|------|-----------|---------|-----------|------|
| NewStreamSniffer struct | 11.31 | 6.82 | POD lifecycle（GC 驱动） | **T1** |
| readStreamOnceAsync.func1 | 16.04 | （SniffTcp 9.49） | PROD async 机制 | **T1** |
| NewPacketSniffer + pool.Put churn | 3.50+17.71 | （SniffQuic 6.31） | PROD packet lifecycle | **T1** |
| BuiltinBytesLocator.Slice | 10.38 | — | PROD 接口装箱 | **T2** |
| NewLinearLocator + LinearLocator.Slice | 2.07+2.17 | — | PROD 接口装箱 | **T2** |
| ExtractCryptoFrameOffset + ReassembleCryptos | 3.11+2.26 | — | PROD 跨调用存活 | **T3** |
| CRYPTO（hmac/sha256/hkdf/aes） | ~57 | — | inherent | 排除 |
| deadline/context/timer | ~24 | — | inherent | 排除 |
| net.SplitHostPort | 5.84 | — | harness | 排除 |

## 5. verifiable_gates（见 frontmatter gates 段）

**两个新 gate**：
- `cpu_profile_review`（H7）：量化「砍分配 → 降 GC CPU」收益闭环。本 Sprint 调研发现 GC 主导 41-50% CPU，T1 池化后 mallocgc/gcBgMarkWorker cum% 应下降。
- `interface_compatibility_check`：lifecycle 重构改变接口/生命周期，grep 所有 `Locator`/`NewStreamSniffer`/`NewPacketSniffer` 外部调用方确保不破坏。这是前 3 Sprint（语义等价）没有的新风险 gate。

**race gate 是最高风险项**：T1 async goroutine 复用 + T3 跨调用存活均涉及并发，race 必跑。

## 6. 编辑规范（Dev 阶段）

- 源码首选 `replace_string_in_file`（L7：禁 PowerShell inline 编辑源码）。
- 代码注释 / commit message **必须英文**（AGENTS.md 硬规则）。
- WSL 命令脚本化（H3）：tmp/*.sh → `wsl bash`，禁 inline `$`。
- sniffing/control 包任何操作先 `make ebpf` 再带 `-tags=$(cat .build_tags)`（F1）。
- `-cpuprofile` 与 `-memprofile` 分两次跑（F4：sample 冲突）。
- 池化纪律（T1）：Put 前 Reset 清零所有字段（buf Reset / data nil / quicCryptos nil / sniffed 空 / cancel 调用），避免跨连接数据污染。

## 7. 开放问题 / Open Questions

- **OQ-S4-1**：T1 async goroutine 复用可能影响读语义（顺序/并发/超时）。**闭环方式**：Dev 实现后跑 `go_test_race` + 语义对照测试（同一输入 stream 改前改后嗅探结果一致）；若 race 失败，回退为「channel 复用但 goroutine 不复用」的保守方案。这是本 Sprint 最高风险点。
- **OQ-S4-2**：T2（接口收敛）是否真依赖 T1（struct 形状）？Dev 实现前评估：若 Locator 内嵌与 Sniffer struct 无关，T2 可解耦为 layer1 并行（降 dag_layers=1，commit_budget=3）。**默认串行**（保守），Dev 可提请解耦。
- **OQ-S4-3**：CPU profile 显示 `sniffHTTPHostHeader` cum 11.70%（flat 1.40%）+ `bytes.Index` cum 7.55%，这两个是**纯 CPU 计算**（非分配驱动），lifecycle 重构不直接覆盖。是否记 Sprint+1（CPU 算法优化，如 bytes.Index 优化）？**记 Sprint+1 候选**（本 Sprint 聚焦 lifecycle，CPU 算法优化是独立方向）。
- **OQ-S4-4**：H7 调研发现「GC 主导 CPU」，若 T1 池化后 GC CPU 下降不明显（如 GC 已被其他包分配驱动），cpu_profile_review gate 如何判 PASS？**判据**：mallocgc cum% 不增 + NewStreamSniffer cum% 不增即 PASS；GC 总量下降为 bonus（非硬指标，因 GC 受全程序分配影响）。
