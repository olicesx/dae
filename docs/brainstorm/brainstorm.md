# Sprint 1 结构化脑暴 — 语义不变的代码精简优化

> 主持人：Remy（Producer）。6 角色，至少 2 次真正分歧。
> 主题：为 dae 做等价重构，降低运行时开销（方向 A Go 内存分配 / 方向 B eBPF C 数据平面）。
> 约束：不改变行为/API；不碰锁合并、文件拆分、测试瘦身。

---

## 参与者

| 角色 | 视角 | 立场倾向 |
|------|------|----------|
| **Kira**（架构） | 可维护性 / 抽象边界 | 倾向保守，反对侵入式改动 |
| **Milo**（性能） | 分配/GC/内联 | 倾向激进，追求零分配 |
| **Nova**（eBPF） | 数据平面 / verifier | 倾向 C 侧极致优化 |
| **Sage**（质量） | 测试/可验证性 | 要求每改必可证等价 |
| **Remy**（制作） | 范围/风险/交付 | 守住"语义不变"红线 |
| **Ivy**（运维） | 可观测/线上影响 | 关心 GC 抖动 / 尾延迟 |

---

## 共识（快速达成）

1. **语义不变是绝对红线**：所有改动必须通过 `semantic_refactor_gate` 既有框架 + 完整 gate（vet/build/test/ebpf-lint/ebpf-sync-check）。本项目已证明对"双实现并存"零容忍（见 `semantic_refactor_gate.go` 注释：each gate either becomes single path or is removed）。
2. **优先复用既有 sync.Pool 模式**：代码库已有 8 处成熟 sync.Pool，新增池化必须沿用同一 New/Reset 规范，不引入新模式。
3. **不动 feature gate**：本 Sprint 是纯 perf，不新增 `SemanticRefactorFeature`，只优化已上线的单条路径。
4. **out-of-scope 严格**：锁合并、巨型文件拆分、测试瘦身明确排除。

---

## 分歧 1 ❗ sync.Pool vs 栈分配（堆分配消除策略）

**Milo**：dns_control.go 的 `make([]byte, ...)`、dnsmessage packing 的临时 slice 全该 sync.Pool 化或上栈，热路径零堆分配是目标。

**Kira**：反对盲目 sync.Pool。① Pool 有 Get/Put + reset 开销，冷路径反而更慢；② Go 逃逸分析下"上栈"若被取地址会逃逸到堆，行为不可预期；③ 既有 `ttlScratchSlice` 已用 `[8]uint32` 栈数组传指针的模式，说明团队认可"小固定上栈、大可变用 Pool"。

**Sage**：必须用 `go build -gcflags='-m'` 验证逃逸，否则"上栈"是空话。

> **裁决（Remy）**：采用 Kira 的分层策略——
> - 固定小 buffer（≤64B，如 TTL/flags）：栈数组传指针（沿用 `ttlScratchSlice` 模式），**强制 gcflags 逃逸验证**。
> - 可变大 buffer（响应报文、批量 batch）：sync.Pool，沿用既有 New 规范。
> - 冷路径（reload/init）：不池化，YAGNI。
> 记为决策 D1。

---

## 分歧 2 ❗ eBPF map lookup 合并 vs verifier 友好性

**Nova**：tproxy.c 有 35 处 map 操作，`parse_ctx_scratch_map`/`pkt_scratch_map`/`conn_state_map` 多处重复 lookup，应合并为单次 lookup + 局部指针复用。

**Sage**：警告——① clang BPF 后端已做死代码消除（DCE），部分"重复 lookup"可能 clang 已优化，盲目合并是无效功甚至引入 verifier 复杂度；② 合并跨函数调用边界的 lookup 会改变 verifier 路径分析；③ scratch map 多为 per-CPU map，lookup 成本极低（~ns），收益存疑。

**Ivy**：线上关心尾延迟，但更怕 verifier 拒载导致 reload 失败。若合并导致 verifier 失败，回滚成本高。

> **裁决（Remy）**：采用 Sage 的保守策略——
> - **先验证 clang 是否已 DCE**：用 `clang -O2 -emit-llvm` + 查看 verifier log，确认哪些 lookup 真冗余。
> - **仅合并 clang 无法证明冗余的**：典型为同一函数内、中间有函数调用阻断了 clang 分析的同 map lookup（如 `conn_state_map` 在 routing core 被多次 lookup）。
> - **scratch map（per-CPU）不合并**：成本太低，收益<风险。
> - 每个 B 任务必须本地 `make ebpf-lint` + `make ebpf-sync-check` + verifier log 对比 instruction count。
> 记为决策 D2。

---

## 其他讨论（无分歧，记录结论）

- **预分配 slice**：routing_matcher_builder.go 构建期已知 rule 数，应 `make([]T, 0, knownCap)`（Milo 提，Kira 同意，YAGNI 适用构建期）。
- **拷贝消除**：dns_cache.go `Clone`/`CloneForReload` 是 COW 快照热点，审查是否能共享不可变前缀（Sage 要求 benchmark 证明无回归）。
- **daedns router**：per-query 响应 buffer 复用，沿用 `udpDNSBufPool`（client.go）模式。

---

## 决策汇总

| ID | 决策 | 影响 |
|----|------|------|
| D1 | 分层分配策略：小固定上栈（gcflags 验证）/ 大可变 Pool / 冷路径不池化 | 所有 A 任务 |
| D2 | eBPF lookup 合并仅限"clang 无法 DCE 的同函数内重复"，scratch map 不动 | B 任务 |
| D3 | 不新增 SemanticRefactorFeature gate，只优化单条路径 | 全 Sprint |
| D4 | 每改必证等价：gate 全过 + 关键路径 benchmark 不回归 | 全 Sprint |

---
---

# Sprint 2 结构化脑暴 — 语义不变的代码精简（bench 驱动 + OQ4）

> 主持人：Remy。6 角色，至少 2 次真正分歧。
> 主题：延续 Sprint 1 方向，**核心区别 = H2 bench 驱动选文件**（降 Sprint 1 的 57% no-op 率）+ 纳入 OQ4（client.go）。
> 输入：[docs/sprint-2/drift-check.md](../sprint-2/drift-check.md)、[docs/sprint-2/runtime-context.md](../sprint-2/runtime-context.md) bench 基线、Sprint 1 OQ4/lessons L1-L8。
> 约束：不改行为/API；不碰锁合并、文件拆分、测试瘦身、fork、eBPF C、冷路径、test-only 函数。

## 共识（基于 drift-check）

1. **H2 是本 Sprint 核心**：静态 grep 选文件（Sprint 1）导致 57% no-op；改为 bench allocs/op 实测驱动，allocs/op=0 的热点**不得设 task**（硬约束）。
2. **H1 修正**：Sprint 1 误标 `make ebpf-test` ignored，本机实跑 PASS → Sprint 2 标 `local=runs`。
3. **H4 扩展 target_files**：T1 纳入 client.go（router.go 的同模块同 udpDNSBufPool 关联文件），不再"机会在隔壁却不能动"。
4. **延续 D1/D4**：分层分配 + 每改必证等价，本 Sprint 沿用。

## 分歧 3 ❗ T3（sniffing QUIC）纳入与否 —— 密码学 no-op 风险

**Milo**（性能）：sniffing 是本 Sprint **最大 bench 热点**（SnuffUdp_QUICMultiPacket 160 allocs/op、SnuffUdp_QUIC 69），每个 QUIC 包都走，必须纳入。

**Nova**（eBPF，本 Sprint 兼 sniffing 视角）：警告——QUIC 嗅探含密码学（`Keys_PayloadDecrypt`=6、`NewKeys`=48），这些 allocs 是密钥派生/HP 的**内禀成本**，语义不可消除。Sprint 1 L2 教训：静态点名 ≠ 可优化。

**Sage**（质量）：若 69-160 allocs 大部分来自密码学，T3 会重蹈 Sprint 1 覆辙（no-op），与 H2"降 no-op"目标矛盾。建议先排除 sniffing。

**Kira**（架构）：sniffing 包无既有 Pool，贸然池化密码学 buffer 有数据残留风险（密钥材料复用）。

> **裁决（Remy）**：**纳入但有条件**——
> - T3 设为 `expected: effective_or_noop`：Dev **必须先量化**密码学 vs 非密码学 allocs 占比（bench + pprof 或代码路径分析）。
> - 仅消除**非密码学**分配（如 map/slice 增长、临时解析 buffer）；密码学 buffer（Keys/NewKeys）**明确排除**。
> - 若量化显示 allocs 全为密码学内禀 → **诚实 no-op**（H2 允许，须有分析论证，非 silent failure）。
> - 密码学 buffer **禁池化**（Kira 的密钥残留顾虑）。
> 记为决策 D5。

## 分歧 4 ❗ T1（OQ4）无 bench，如何证非回归

**Milo**：OQ4 的 sendStreamDNS/queryHTTPS/lookupType 是每查询热路径，应**新增 bench**量化收益（lookupType Pack→PackBuffer 前后 allocs）。

**Kira/Sage**：反对。① daedns 包当前**无任何 bench**（实跑 `ok 0.004s`），新增 bench = 引入测试基础设施，属 scope 膨胀（用户明确排除"测试瘦身"，反向新增同理应克制）；② Sprint 1 L4 已充分论证 PackBuffer 安全条件（同步消费），T1 可靠 race+vet+build+test + L4 人工论证；③ OQ4 是用户指定任务，"加 bench"不是用户要求。

**Ivy**（运维）：关心的是线上 GC 抖动。无 bench 就无法量化，但每查询 buffer（req/lengthBuf/respBuf）确实是热路径，收益方向明确（lengthBuf 上栈 [2]byte 是确定性零成本）。可接受"无 bench + 论证"。

> **裁决（Remy）**：**不加 bench，靠论证 + L4**——
> - T1 验证 = race(daedns) + vet + build + test + **L4 安全条件逐条核对**（PackBuffer 同步消费、lengthBuf 上栈）。
> - 如 Dev 实施中判断收益不明朗，**可选**加一个 lookupType bench（非强制，须显式声明不属硬 gate）。
> - 记 `bench_coverage: none` 到 plan，诚实标注 T1 无法用 bench 证非回归。
> 记为决策 D6。

## 其他讨论（无分歧，记录结论）

- **commit_budget=2 的张力**（Remy 提出）：公式 ⌈3/3⌉+0+1=2 对 3 任务偏紧。Milo 指出这是"因果倒置"反例的镜像——公式 ⌈n/3⌉ 内含期望 no-op 率，H2 降 no-op 后可能欠预算。裁决：遵循用户指定公式（D7），hard_cap=10 留余量，若 3 任务全有效走文档化解锁（记 progress.md）。
- **T2 高置信**：relayCopyBufferPool 已存在于 tcp_copy_engine.go:18，bench 仍 8-9 allocs/op → 几乎肯定有未走池的分配（Sage/Milo 一致同意，无分歧）。
- **排除项确认**：QuicInitialEndToEnd（fork）、CloneCacheForReload10000（冷 reload，Sprint 1 先例）、DnsCache_Clone/FillInto*（L2 test-only）—— 全员同意排除，无分歧。

## 决策汇总（Sprint 2 追加）

| ID | 决策 | 影响 |
|----|------|------|
| D5 | T3 sniffing 纳入但有条件：先量化密码学占比，仅消除非密码学 allocs，密码学 buffer 禁池化，全内禀则诚实 no-op | T3 |
| D6 | T1 不加 bench，靠 race+vet+L4 论证；Dev 可选加 lookupType bench（非硬 gate） | T1 |
| D7 | commit_budget 遵循用户公式=2；hard_cap=10 留余量；全有效则文档化解锁 | blast_radius |
| D8 | 沿用 Sprint 1 D1（分层分配）+ D4（每改必证等价） | 全 Sprint |

---
---

# Sprint 3 结构化脑暴 — 基于 H5 的内存优化（bench + memprofile 双验证）

> 主持人：Remy。6 角色，至少 2 次真正分歧。
> 主题：延续 Sprint 1/2 内存优化。**核心区别 = 应用 H5**——Producer 规划阶段即用 memprofile 验证每个热点的生产相关性，从源头过滤 harness 噪声 task（Sprint 2 T2 是 Dev 阶段才发现 harness noise）。
> 输入：[docs/sprint-3/drift-check.md](../sprint-3/drift-check.md)、[docs/sprint-3/runtime-context.md](../sprint-3/runtime-context.md) §H5 分类表、Sprint 2 hill-climbing（H5 来源 + sniffing lifecycle Sprint+1 候选）。
> 约束：不改行为/API；不碰锁合并、文件拆分、测试瘦身、fork、eBPF C、冷路径、test-only 函数；**sniffing lifecycle/接口重构超语义等价边界→Sprint+1**（用户硬约束）。

## 共识（基于 drift-check + H5 扫描）

1. **H5 是本 Sprint 核心**：memprofile 区分生产 vs harness，harness 噪声热点**不得设 task**（硬约束）。
2. **零漂移**：连续 3 Sprint 环境/工具链一致（drift-check §1）。
3. **L9 方法论固化**：Sprint 2 T2 的事后 memprofile 发现（L9）→ Sprint 3 前置到 Producer 阶段（H5）。
4. **延续 D1/D4/D8**：分层分配 + 每改必证等价。

## 分歧 5 ❗ WriteToBufferFlush（60 allocs/3.6MB，最大热点）纳入与否

**Milo**（性能）：这是全量扫描 allocs/op 与 B/op 双第一的热点（60 allocs/op, 3.6MB/op），每 TCP 嗅探连接 relay 都走 ConnSniffer.WriteTo，必须纳入，潜在收益最大。

**Sage**（质量）：先等 memprofile。Sprint 2 T2 教训（L9）——bench allocs 可能全是 harness。3.6MB/op 配 60 allocs 太可疑，像是 bench 每轮重建大对象。

> **裁决前 memprofile 揭示**：pprof 显示 `net.IPv4` flat **76.58%** + `net.(*sysListener).listenTCPProto` **19.15%** = **95.73% 是 bench 每轮 net.IPv4() 构造 + net.Listen 起 TCP listener**；生产 `(*ConnSniffer).WriteTo` cum 仅 2.29%（979B，io.CopyBuffer dst 增长，亦是 bench 的 bytes.Buffer dst）。

> **裁决（Remy）**：**H5 过滤，不设 task**。最大热点 95%+ 为 bench 工件，生产 WriteTo flat=0。这是 H5 价值的标杆案例——**bench 表面最大 = harness 最重**。记为决策 D9（H5 过滤标杆）。改 bench harness 属 test-only（L2 YAGNI），本 Sprint 不动。

## 分歧 6 ❗ 仅剩 errStrLower 一个 residual，Sprint 3 是否"过于薄" / 该不该诚实报告"无可优化真热点"

**Remy**（制作）：H5 过滤后，4 候选里 D 过滤、B（QUIC 59% crypto + Sprint-2-exhausted）、C（SniffTcp lifecycle-boundary）排除，只剩 A 的 errStrLower（错误路径 strings.ToLower alloc）。Sprint 3 = 1 个小 task。这"薄"得近乎无 Sprint。是否该诚实报告"无可优化真热点"？

**Milo**（性能）：反对轻易判无。errStrLower 是**真实生产 alloc**（ICMP-refused 处理，strings.ToLower 每次拷贝整个错误字符串），虽在错误路径非稳态，但消除它零成本零风险（零分配大小写不敏感匹配）。1 个真实有效 task 仍值得做。

**Kira**（架构）：同意 Milo——errStrLower 语义保持可证（ASCII 错误消息大小写不敏感子串匹配，结果逐位一致）。但须诚实标注 bulk（context/timer/struct/map）inherent，不得为凑数改语义。

**Sage**：H5 的正确结论不是"零 task"而是"1 个验证过的生产 task + 3 个有据排除"。这正是 H5 比纯 bench 驱动（Sprint 2 T2 事后才发现）更优的证据。

**Ivy**（运维）：线上 UDP proxy 频繁遇到 unreachable peer 时，ICMP-refused 处理路径的 alloc 累积会加 GC 压力；errStrLower 消除对尾延迟场景有益。值得做。

> **裁决（Remy）**：**设 T1 = errStrLower，不判"零真热点"**——
> - errStrLower 是 H5 通过过滤的真实生产 residual（非 harness、非 crypto、非 lifecycle-boundary）。
> - expected `effective_small`（零分配匹配，bench 是否下降取决于 bench 触发率，memprofile_review 为决定性 gate）。
> - bulk inherent（context.WithTimeout ×2 / &UdpEndpoint{} / lifecycleProfile / registerEndpoint map）**Dev 须文档化**为 inherent no-op，不得改语义凑数。
> - thin Sprint 是 H5 应用于已优化 2 Sprint 代码库的**正确预期**（非失败）；Sprint+1 建议改主题为 lifecycle refactor。
> 记为决策 D10。

## 分歧 7 ❗ sniffing lifecycle（C，三次确认超边界）是否破例纳入

**Milo**：C（SniffTcp_TLS 18 allocs）主 allocs 是 NewStreamSniffer 11% + async-goroutine 19% = 30%，若池化 StreamSniffer 是大收益。Sprint 1/2/3 三次扫到都因"lifecycle"排除，是否本 Sprint 破例？

**Kira/Sage**：坚决反对破例。① StreamSniffer 池化涉接口/生命周期调整（跨调用存活 s.quicCryptas 等），**超语义等价边界**（用户硬约束明确排除）；② 三次排除恰是强信号——该类优化需独立 Sprint（lifecycle refactor，非 semantic-preserving），不应在语义保持 Sprint 里硬塞；③ 破例会模糊 Sprint 主题边界，破坏 drift-check 的边界纪律。

> **裁决（Remy）**：**不破例，C 排除**。三次跨 Sprint 数据点（Sprint 1 OQ / Sprint 2 hill-climbing Sprint+1 / Sprint 3 memprofile 复核）一致确认 sniffing lifecycle 超 semantic-preserving 边界。**记 Sprint+1 候选：建议 Sprint 4 改主题为"lifecycle refactor"**（明确非语义保持，独立 gate 设计）。记为决策 D11。

## 决策汇总（Sprint 3 追加）

| ID | 决策 | 影响 |
|----|------|------|
| D9 | H5 过滤标杆：WriteToBufferFlush（60/3.6MB）memprofile 证 95.73% harness → 不设 task；bench 表面最大≠生产最重 | 全 Sprint H5 纪律 |
| D10 | T1=errStrLower（H5 通过的真实生产 residual），expected effective_small；bulk inherent 文档化不凑数；thin Sprint 是 H5 正确预期 | T1 |
| D11 | sniffing lifecycle 不破例（三次超边界），记 Sprint+1 候选建议改主题 lifecycle refactor | scope 边界 |
| D12 | 沿用 D1/D4/D8；H5 memprofile 须逐包跑（F3） | 全 Sprint |
