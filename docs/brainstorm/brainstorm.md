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
