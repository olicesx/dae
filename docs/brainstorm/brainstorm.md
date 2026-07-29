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
