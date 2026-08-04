---
project: dae
sprint: 5
sprint_theme: "Tech debt cleanup + measurement precision upgrade (H8 first application) / 技术债清理 + 测量精度升级（H8 首次应用）"
content_language: bilingual
content_language_source: inferred
model_context_window: 1000000
model_context_window_source: default
schema_version: v5.0
current_phase: done
branch: kdae
last_updated: 2026-08-04
sprint_current: 6
constraint_policy: stability_hardening_allowed
sprint_latest_status: "Sprint 1-6 全部 fully closed。Sprint 6 PASS（首次验证型 Sprint stability_hardening_allowed）：T1 对 23 游离 commit（巨型文件拆分+5 bug fix+fork bump，59 files/+8608/-7018）补齐权威验证，10/10 gate pass（race/ebpf/bench/make dae validate），0 回归，commits_used=1（149b3ce9 docs only）；L19/L20 新 lesson，H11/H12 proposed。Sprint 5 PASS：T1 删 108 测试 / T2 sniffHTTPHostHeader -36..-43% / T3 H8 首次应用。"
---

# dae — PROJECT_BRIEF (Sprint 1)

> dae 是基于 Linux 内核 eBPF 的高性能透明代理。本 Sprint 对现有代码做**语义不变的等价重构**，降低运行时开销。本文件由 Remy（Producer）维护，Dev/QA 阶段过渡时更新第 7、8 节。

---

## 1. 项目概述 / Project Overview

dae 使用 eBPF 在内核态做流量分流（traffic splitting），对直连流量绕过用户态代理转发，从而把性能损耗降到最低。

- **语言 / Language**: Go 1.26 + eBPF C (cilium/ebpf)
- **许可 / License**: AGPL-3.0
- **关键技术 / Key Tech**: eBPF, QUIC, 透明代理, DNS routing
- **目标平台 / Target**: Linux only（内核态 eBPF）

## 2. 目标 / Goals

本 Sprint（语义不变的精简优化，两个方向）：

- **方向 A — Go 内存分配优化（热路径）**：sync.Pool 化高频临时对象、预分配 slice 容量、消除不必要拷贝。
- **方向 B — eBPF C 数据平面精简**：`control/kern/tproxy.c` 减少冗余 map lookup、合并重复检查、精简栈使用。
- **整体**：所有改动**等价**（不改行为/API），且通过既有 `semantic_refactor_gate` + 完整验证 gate。

## 3. 非目标 / Non-Goals (Out-of-Scope)

本 Sprint **明确不做**：

- 锁合并 / 重排（lock consolidation/reordering）
- 巨型文件结构拆分（如 dns_control.go 3635 行、udp_endpoint_pool.go 2557 行的物理拆分）
- 测试瘦身 / 批量删测试
- 新增 feature gate（`SemanticRefactorFeature`）或新协议
- 任何行为/API 变更

## 4. 背景 / Background & Motivation

代码库已有 8 处成熟的 sync.Pool（`control/dns.go:responseSlotPool`、`udp_endpoint_pool.go:udpEndpointReplyObjects`、`dns_control.go:dnsResponseBufPool` 等），说明团队已有分配优化意识与实践，但热路径仍存在未池化的 `make([]byte,...)` 与可预分配的 slice。eBPF 侧 `tproxy.c`（3328 行）含 35 处 map 操作，其中部分为 clang BPF 后端无法 DCE 的真冗余。本 Sprint 在不扩大范围的前提下收割这些低风险、高确定性的性能收益。

## 5. 架构与关键组件 / Architecture & Key Components

```
dae/
├── cmd/              CLI 入口
├── control/          核心控制面、eBPF 交互、DNS（本 Sprint 主战场）
│   ├── dns_control.go (3635)   DNS 路由编排
│   ├── dns.go (1445) / dns_cache.go (695)   DNS 处理与缓存
│   ├── udp_endpoint_pool.go (2557)          UDP 端点池
│   ├── udp_ordered_dispatcher.go (545)      有序 UDP ingress
│   ├── udp_reply_dispatcher.go (446)        UDP 回复
│   ├── udp_ingress_batch.go (123)           UDP 批量 ingress
│   ├── routing_matcher_builder.go (949)     路由匹配构建
│   ├── semantic_refactor_gate.go            语义重构 feature gate 框架（仅参考，不改）
│   └── kern/tproxy.c (3328)                 eBPF 主程序（方向 B）
├── component/daedns/router.go (753)         DNS 路由（方向 A）
└── config/ common/ pkg/ ...
```

关键文件：见 [docs/sprint-1/plan.md](docs/sprint-1/plan.md) 的 `target_files`。

## 6. 技术栈 / Tech Stack

| 项 | 版本/值 |
|----|---------|
| Go | 1.26.0 (linux/amd64) |
| 内核 | 6.18.33.2-microsoft-standard-WSL2 |
| clang | 18.1.3 (Ubuntu) |
| bpftool / make | 就绪 |
| `.build_tags` | `trace` |
| fork 依赖 | `github.com/olicesx/quic-go`、`github.com/olicesx/outbound`（见 go.mod replace） |
| eBPF lib | cilium/ebpf v0.20.0 |

## 7. 当前阶段与状态 / Current Phase & Status

| 时间 | 阶段 | 负责人 | 状态 |
|------|------|--------|------|
| 2026-07-29 | Planning（脑暴+plan+brief） | Remy | ✅ 完成 |
| 待定 | Dev 实现（A 并行 / B 串行） | Dev | 待启动 |
| 待定 | QA 验证（gate 全过 + benchmark） | QA | 待启动 |

> 阶段过渡时由 Remy 更新本节。

## 8. 交接上下文 / Handoff Context

### Producer → Dev
- 本文件 + [docs/sprint-1/plan.md](docs/sprint-1/plan.md)（task DAG + target_files + gates）+ [docs/brainstorm/brainstorm.md](docs/brainstorm/brainstorm.md)（决策 D1-D4）。
- 运行时基线见 [docs/sprint-1/runtime-context.md](docs/sprint-1/runtime-context.md)。
- 编辑规范：源码首选 `replace_string_in_file`；代码注释/commit **必须英文**（AGENTS.md 硬规则）。

### Dev → QA（待 Dev 完成后填充）
- _（占位：Dev 完成后在此写明改动文件清单、benchmark 前后值、已知限制）_

## 9. 风险与缓解 / Risks & Mitigations

| 风险 | 等级 | 缓解 |
|------|------|------|
| sync.Pool 误用（Put 后仍引用 / 未 reset）导致数据污染 | 高 | 沿用既有 New/Reset 规范；QA 跑 race test（`go test -race`） |
| eBPF lookup 合并触发 verifier 拒载 | 中 | 决策 D2：先验证 clang DCE，仅合并真冗余；对比 instruction count |
| "上栈"实际逃逸到堆（无效优化） | 中 | 决策 D1：强制 `gcflags='-m'` 验证逃逸 |
| 语义漂移（无意中改行为） | 高 | 既有 `semantic_refactor_gate` + 完整 gate；不碰 feature gate |
| 热点文件过大（dns_control 3635 行）导致改动易误伤 | 中 | 单 task ≤3 文件；以 go vet/build/test 作集成 gate |

## 10. 验收标准 / Acceptance Criteria

1. `go vet ./...` 通过
2. `go build -tags=$(cat .build_tags) ./...` 通过
3. `go test ./control/... ./component/...` 通过（含 race 抽检）
4. `make ebpf-lint` 零 warning
5. `make ebpf-sync-check` 通过（Go 绑定与 C 一致）
6. 关键热路径 benchmark 不回归（dns/udp dispatch）；若有提升则记录前后值
7. 无行为/API 变更（config 语言、CLI、错误码不变）

## 11. 任务分解 / Task Breakdown

详见 [docs/sprint-1/plan.md](docs/sprint-1/plan.md) § task DAG。摘要：

- **方向 A（Go，并行）**：A1 DNS 热路径分配 / A2 UDP dispatcher 分配 / A3 DNS cache 拷贝消除 / A4 routing matcher 预分配 / A5 daedns router 分配
- **方向 B（eBPF C，串行）**：B1 tproxy.c routing 路径 lookup 合并 → B2 tproxy.c conntrack 路径 lookup 合并

## 12. 度量与成功指标 / Metrics & Success Criteria

| 指标 | 基线 | 目标 |
|------|------|------|
| 热路径堆分配次数（dns/udp dispatch bench `allocs/op`） | 待 Dev 记录基线 | 不增，争取下降 |
| tproxy.c verifier instruction count | 待 Dev 记录基线 | 不增 |
| gate 通过率 | — | 100% |
| 代码行净变化 | — | 应为净减或小幅波动（精简而非膨胀） |

## 13. 决策记录 / Decision Log (ADRs)

| ID | 决策 | 来源 |
|----|------|------|
| D1 | 分层分配：小固定上栈（gcflags 验证）/ 大可变 Pool / 冷路径不池化 | 脑暴分歧 1 |
| D2 | eBPF lookup 合并仅限"clang 无法 DCE 的同函数内重复"，scratch map 不动 | 脑暴分歧 2 |
| D3 | 不新增 SemanticRefactorFeature gate | 共识 |
| D4 | 每改必证等价（gate 全过 + benchmark 不回归） | 共识 |

## 14. 开放问题 / Open Questions

1. `make ebpf-test` 需真实 kernel，本机 WSL2 kernel 6.18 是否覆盖 CI matrix（6.6/6.12）？— 标 ci_gate ignored，本机跳过，依赖 CI。
2. dns_control.go:38 的 `make([]byte, 1024)` 是否为 `dnsResponseBufPool` 的 New 函数体？— Dev 实现前需确认，避免重复池化。
3. quic-go/outbound 为 fork 依赖，本 Sprint 不改 fork 代码；若优化触及 fork API，提 Issue 上游。

---
---

# dae — PROJECT_BRIEF (Sprint 2 追加)

> Sprint 2 延续 Sprint 1「语义不变的代码精简」方向。**核心区别 = H2 bench 驱动选文件**（降 Sprint 1 的 57% no-op 率）+ 纳入 OQ4（client.go）。
> Sprint 1 章节（上）保持不变；以下为 Sprint 2 增量。详细文档见 [docs/sprint-2/](docs/sprint-2/)。

## Sprint 2 目标 / Goals

- **T1（OQ4，用户指定）**：daedns `client.go` per-query buffer 池化（sendStreamDNS/queryHTTPS/lookupType），复用 udpDNSBufPool。H4：target_files 扩展到 client.go（router.go 同模块关联文件）。
- **T2（H2 bench 驱动）**：tcp relay copy 路径未池化分配消除（relayCopyBufferPool 已存在仍 8-9 allocs/op）。
- **T3（H2 bench 驱动）**：sniffing QUIC 嗅探非密码学分配消除（69-160 allocs/op，先量化密码学占比）。

## Sprint 2 非目标 / Out-of-Scope

锁合并/重排（Sprint+3 候选）、巨型文件拆分、测试瘦身、行为/API/config 变更、fork（quic-go/outbound）、eBPF C（tproxy.c）、冷路径（CloneCacheForReload）、test-only 函数（DnsCache_Clone/FillInto*，L2）。

## Sprint 2 blast_radius / task_sizing

| 项 | 值 |
|----|----|
| task_count | 3（T1/T2/T3 全并行） |
| strong_coupling | 0 |
| commit_budget | 2（⌈3/3⌉+0+1，hard_cap=10） |
| topology | parallel（dag_layers=1） |

## Sprint 2 验收标准 / Acceptance Criteria

1. `go vet/build/test -tags=trace ./...` 通过
2. `go test -race -tags=trace ./component/daedns/... ./control/... ./component/sniffing/...` 通过（T1/T2/T3 Pool 改动）
3. `make ebpf-test` 本机 **runs（PASS，H1：不再 ignored）** + `make ebpf` EXIT=0
4. bench `allocs/op` 不回归；T2/T3 有效则下降；allocs=0 热点不得设 task（H2）
5. 无行为/API/config 变更

## Sprint 2 第 7 节更新 / Phase Status（Sprint 2）

| 时间 | 阶段 | 负责人 | 状态 |
|------|------|--------|------|
| 2026-07-29 | Sprint 2 Planning（drift-check + bench 扫描 + plan + 脑暴） | Remy | ✅ 完成 |
| 待定 | Sprint 2 Dev（T1/T2/T3 全并行） | Dev | 待启动 |
| 待定 | Sprint 2 QA（gate + bench 非回归） | QA | 待启动 |

> Sprint 1 已 QA 签署 PASS（见 [docs/qa/qa-signoff-1.md](docs/qa/qa-signoff-1.md)），Sprint 1 第 7 节状态保持历史记录。

## Sprint 2 第 8 节更新 / Handoff Context

### Producer → Dev（Sprint 2）
- 本文件 + [docs/sprint-2/plan.md](docs/sprint-2/plan.md)（task DAG + target_files + gates + H1/H2 验证）+ [docs/brainstorm/brainstorm.md](docs/brainstorm/brainstorm.md) Sprint 2 段（决策 D5-D8）。
- 基线 + bench 数据：[docs/sprint-2/runtime-context.md](docs/sprint-2/runtime-context.md)（含 F1/F2 必读发现 + bench 基线表）。
- drift 依据：[docs/sprint-2/drift-check.md](docs/sprint-2/drift-check.md)（零 context drift / L1-L8 全规避 / fidelity 100% gated）。
- **Dev 必读**：control 包操作先 `make ebpf` 再带 `-tags=trace`（F1）；命令脚本化 tmp/*.sh（H3）；注释/commit 英文。
- T3 先量化密码学占比再动手（D5）；T1 不加 bench 靠 L4 论证（D6）。

## Sprint 2 关键文档索引

| 文档 | 用途 |
|------|------|
| [docs/sprint-2/plan.md](docs/sprint-2/plan.md) | task DAG / target_files / verifiable_gates / task_sizing |
| [docs/sprint-2/drift-check.md](docs/sprint-2/drift-check.md) | 4 项 drift 检查 + Evals 回归（H1/H2 命中） |
| [docs/sprint-2/runtime-context.md](docs/sprint-2/runtime-context.md) | 工具链基线 + F1/F2 发现 + bench 基线表 |
| [docs/sprint-2/progress.md](docs/sprint-2/progress.md) | Trace Log + gate 状态（Dev/QA 填） |

---

# dae — PROJECT_BRIEF (Sprint 3 追加)

> Sprint 3 延续 Sprint 1/2 内存优化方向。**核心区别 = 应用 H5（bench + memprofile 双验证）**——Producer 规划阶段即用 memprofile 验证每个热点的生产相关性，从源头过滤 harness 噪声 task（Sprint 2 T2 是 Dev 阶段才发现）。
> 以下为 Sprint 3 增量。详细文档见 [docs/sprint-3/](docs/sprint-3/)。

## Sprint 3 目标 / Goals

- **T1（H5 验证后的唯一生产 residual）**：消除 `UdpProxyDial cache=miss` create 路径中 `errStrLower` 的 `strings.ToLower` 冗余字符串分配（control/udp_endpoint_pool.go:1235，零分配大小写不敏感子串匹配），并文档化 bulk inherent allocs（context/timer/struct/map）。
- **整体**：应用 H5——对全部 allocs/op>0 热点跑 memprofile 分类，harness 噪声不得设 task。

## Sprint 3 非目标 / Out-of-Scope

- **WriteToBufferFlush（60 allocs/3.6MB）**：H5 memprofile 证 95.73% harness（net.IPv4 76.58% + net.listenTCPProto 19.15%），生产 WriteTo flat=0 → **H5 过滤，不设 task**。
- **Sniffer_SniffUdp_QUIC（67/160）**：59% crypto-inherent + 非密码学 Sprint-2-exhausted 或 lifecycle-boundary → 排除。
- **Sniffer_SniffTcp_TLS/HTTP（18/16）+ async-read 变体**：主 allocs 为 sniffer-lifecycle 重构（Sprint 1/2/3 三次确认超语义等价边界）→ 排除，记 Sprint+1。
- 锁合并/重排、巨型文件拆分、测试瘦身、行为/API/config 变更、fork、eBPF C、冷路径、test-only 函数。

## Sprint 3 blast_radius / task_sizing

| 项 | 值 |
|----|----|
| task_count | 1（T1，serial） |
| strong_coupling | 0 |
| commit_budget | 2（⌈1/3⌉+0+1，hard_cap=10） |
| topology | serial（dag_layers=1） |
| 预期 no-op 率 | T1 expected effective_small（errStrLower 真实消除）；bulk inherent 文档化非 task |

## Sprint 3 验收标准 / Acceptance Criteria

1. `go vet/build/test -tags=trace ./...` 通过
2. `go test -race -tags=trace ./control/...` 通过（T1 涉及 udp_endpoint_pool）
3. `make ebpf-test` 本机 **runs（PASS）** + `make ebpf` EXIT=0
4. **memprofile_review（H5 决定性 gate）**：改后 memprofile 确认 `strings.ToLower`/`errStrLower` flat 消失；bulk inherent（context/timer/struct/map）flat 保持
5. bench `allocs/op` 不回归（UdpProxyDial/cache=miss；errStrLower 命中则降，未命中允许持平——memprofile 为准）
6. 无行为/API/config 变更；`isConnectionRefused` 返回值逐位一致

## Sprint 3 第 7 节更新 / Phase Status（Sprint 3）

| 时间 | 阶段 | 负责人 | 状态 |
|------|------|--------|------|
| 2026-07-29 | Sprint 3 Planning（drift-check + H5 memprofile 分类 + plan + 脑暴） | Remy | ✅ 完成 |
| 待定 | Sprint 3 Dev（T1 errStrLower + bulk inherent 文档化） | Dev | 待启动 |
| 待定 | Sprint 3 QA（gate + memprofile 复核） | QA | 待启动 |

> Sprint 1 已 QA 签署 PASS（[docs/qa/qa-signoff-1.md](docs/qa/qa-signoff-1.md)）；Sprint 2 状态见其第 7 节。

## Sprint 3 第 8 节更新 / Handoff Context

### Producer → Dev（Sprint 3）
- 本文件 + [docs/sprint-3/plan.md](docs/sprint-3/plan.md)（task DAG + memprofile flat% 证据 + gates + H5 验证）+ [docs/brainstorm/brainstorm.md](docs/brainstorm/brainstorm.md) Sprint 3 段（决策 D9-D12）。
- H5 分类证据：[docs/sprint-3/runtime-context.md](docs/sprint-3/runtime-context.md) §H5 表（4 候选 flat% 逐项）。
- drift 依据：[docs/sprint-3/drift-check.md](docs/sprint-3/drift-check.md)（零漂移 / L1-L9 全规避 L9 成核心 / fidelity 100% gated 脚本假阴性→H6）。
- **Dev 必读**：control 包先 `make ebpf` 再带 `-tags=trace`（F1）；memprofile 须逐包跑（F3，-memprofile 不可跨包）；命令脚本化 tmp/*.sh（H3）；注释/commit 英文。
- **T1 纪律**：只改 errStrLower（零分配大小写不敏感匹配）；bulk inherent（context/timer/struct/map）须文档化为 inherent no-op，**不得改语义凑数**。

## Sprint 3 关键文档索引

| 文档 | 用途 |
|------|------|
| [docs/sprint-3/plan.md](docs/sprint-3/plan.md) | task DAG（含 memprofile flat% 证据）/ verifiable_gates / task_sizing |
| [docs/sprint-3/drift-check.md](docs/sprint-3/drift-check.md) | 4 项 drift + Evals（H1/H2/H3 通过，H5 首次应用）+ H6 发现 |
| [docs/sprint-3/runtime-context.md](docs/sprint-3/runtime-context.md) | 工具链基线 + H5 分类表（4 候选 flat%）+ F3 发现 |
| [docs/sprint-3/progress.md](docs/sprint-3/progress.md) | Trace Log + gate 状态 + H5 应用证据（Dev/QA 填） |

---

# dae — PROJECT_BRIEF (Sprint 4 追加)

> Sprint 4 **首次解除「语义等价」约束**（constraint_policy: lifecycle_refactor_allowed，用户显式解除）。**核心 = 把 Sprint 1-3 三次 deferred 的 sniffing lifecycle-boundary 候选纳入**（Sprint 2/3 hill-climbing 各记一次）+ **引入 H7 CPU profile 方法论**（bench/memprofile 之外的第三维度）。
> ⚠️ Sprint 4 的 Goals/Non-Goals 取代 Sprint 1-3 的「语义不变」方向；以下为 Sprint 4 增量。详细文档见 [docs/sprint-4/](docs/sprint-4/)。

## Sprint 4 目标 / Goals（取代 Sprint 1-3 的语义等价方向）

- **T1（对象池化，TCP+UDP 双路径）**：`NewStreamSniffer`/`NewPacketSniffer` Sniffer struct + `readStreamOnceAsync` goroutine/channel 复用（mem flat 11.31%+16.04%+3.50%+17.71%；CPU cum 6.82%+9.49%+6.31%）。
- **T2（接口收敛，依赖 T1）**：`BuiltinBytesLocator`/`LinearLocator` 装箱入 `Locator` 接口的分配消除（mem flat TLS 10.38% / QUIC 4.24%）。
- **T3（跨调用存活，UDP）**：`ExtractCryptoFrameOffset`/`ReassembleCryptos` 的 `CryptoFrameOffset` 经 `s.quicCryptos` 跨调用复用（mem flat 3.11%+2.26%）。
- **方法论**：应用 **H7（CPU profile 新维度）**——Producer 阶段跑 CPU profile 揭示「GC 主导 CPU（41-50%）→ alloc 与 CPU 热点收敛」；延续 H5（memprofile）。

## Sprint 4 非目标 / Out-of-Scope

> 注：Sprint 1 的「锁合并/重排、巨型文件拆分」两项 Non-Goals 已**被本 Sprint lifecycle 主题覆盖**（不再作为硬 Non-Goal）；本 Sprint 明确不做的如下：

- ❌ CRYPTO inherent（hmac/sha256/hkdf/aes ≈ 57%）—— 算法本质。
- ❌ deadline/context/timer inherent（≈ 24% TLS）—— 超时语义。
- ❌ 测试瘦身 / 批量删测试。
- ❌ 新协议 / 新 feature。
- ❌ 行为/API/config 变更（嗅探结果 domain/err 逐位一致；仅生命周期/分配方式变）。
- ❌ vendor / vmlinux-*.h / fork（quic-go、outbound）。
- ❌ eBPF C（tproxy.c）。
- ❌ net.SplitHostPort.func1（harness）、冷路径、test-only 函数。

## Sprint 4 blast_radius / task_sizing

| 项 | 值 |
|----|----|
| task_count | 3（T1/T3 layer1 并行，T2 layer2 依赖 T1） |
| strong_coupling | 1（T2 接口收敛触碰 T1 池化后的 struct 形状） |
| bug_reserve | 1（lifecycle 重构 race/语义风险高于前 3 Sprint） |
| commit_budget | 4（dag_layers 2 + strong_coupling 1 + bug_reserve 1，hard_cap=10） |
| topology | hybrid（layer1 并行 + layer2 串行） |

## Sprint 4 验收标准 / Acceptance Criteria

1. `go vet/build/test -tags=trace ./...` 通过
2. `go test -race -tags=trace ./component/sniffing/...` 通过（T1/T2/T3 均涉及并发，race 必跑）
3. `make ebpf-test` 本机 runs（PASS）+ `make ebpf` EXIT=0
4. **memprofile_review（H5）**：T1/T2/T3 各 flat 下降；CRYPTO inherent 保持
5. **cpu_profile_review（H7 新 gate）**：runtime.mallocgc + NewStreamSniffer cum% 不增（砍分配 → 降 GC CPU 收益闭环）
6. **interface_compatibility_check（新 gate）**：grep 所有 Locator/NewStreamSniffer/NewPacketSniffer 外部调用方不破坏
7. bench `allocs/op` 不回归；T1（Sniffer/async 池化）命中则 SniffTcp_* + async_read 显著降
8. 嗅探行为不变（domain/err 逐位一致）；仅生命周期/分配方式变化

## Sprint 4 第 7 节更新 / Phase Status（Sprint 4）

| 时间 | 阶段 | 负责人 | 状态 |
|------|------|--------|------|
| 2026-07-29 | Sprint 4 Planning（drift-check + H7 CPU + H5 mem + plan） | Remy | ✅ 完成 |
| 2026-07-29 | Sprint 4 Dev（T1 池化 / T2 接口收敛 / T3 跨调用存活） | Dev | ✅ 完成（3 commits：97d1c314 / 3bed4bef / 1352dd85） |
| 2026-07-29 | Sprint 4 QA（gate + cpu_profile_review + interface_compat） | QA | ✅ PASS（[docs/qa/qa-signoff-4.md](docs/qa/qa-signoff-4.md)，head_commit 1e1fca20） |

> Sprint 1-3 已完成并 commit；Sprint 1 已 v5.0 复核 PASS（[docs/qa/qa-signoff-1.md](docs/qa/qa-signoff-1.md)）；Sprint 2/3 状态见其第 7 节。

## Sprint 4 第 8 节更新 / Handoff Context

### Dev → QA（Sprint 4）
- **改动文件清单**：`component/sniffing/{sniffer.go, internal/quicutils/relocation.go, quic.go, tls.go, benchmark_test.go}`（`conn_sniffer.go` 列 T1 target 但实际 read-only 未改）。
- **bench 前后要点**（7/7 全降，0 回归）：SniffTcp_TLS 18→13、SniffTcp_HTTP 16→12、SniffUdp_QUIC 67→60、SniffUdp_QUICMultiPacket 160→142（跨调用存活收益最大）、deadline_sync_read 8→5（生产 TCP 主路径）。
- **H7 GC 收益**：gcBgMarkWorker cum% 27.26%→10.32%（**-16pp**，H7 收益闭环核心）；NewStreamSniffer CPU 层消除；mallocgc 14.20%→14.30%（噪声内不增，OQ-S4-4 marginally met）。
- **已知限制（OQ）**：① readStreamOnceAsync flat 26% 非 `.func1` 闭包（已消除），是 bench `bytes.Reader` 强制 async 的 harness 偏差（L14），生产 `net.Conn` 走 deadline 路径 0 goroutine；② SniffTcp cum% 相对上升 +10pp 是分母效应（GC 总量降致 APP 占比升），非回归。
- **文档**：[docs/sprint-4/progress.md](docs/sprint-4/progress.md)（Trace Log + bench 基线表 + H7 基线表）；commits `97d1c314` / `3bed4bef` / `1352dd85`。

### QA → done（Sprint 4）
- **verdict = PASS**（[docs/qa/qa-signoff-4.md](docs/qa/qa-signoff-4.md)，head_commit `1e1fca20`）：local_gate + ci_gate + manual_gate 全过；H5/H7 决定性 gate 独立复现 Dev 数据；interface_compatibility 无破坏性变更；commits_used = 3/4。
- **L4 完成**（[docs/sprint-4/hill-climbing.md](docs/sprint-4/hill-climbing.md)）：新增 L12-L14；H7 applied（强生效）、H8 proposed；no-op 率连续 2 Sprint 为 0%。Sprint 4 fully closed。

## Sprint 4 关键文档索引

| 文档 | 用途 |
|------|------|
| [docs/sprint-4/plan.md](docs/sprint-4/plan.md) | task DAG（含 CPU+mem 双证据）/ verifiable_gates（+cpu_profile_review +interface_compat）/ task_sizing |
| [docs/sprint-4/drift-check.md](docs/sprint-4/drift-check.md) | 4 项 drift + Evals（H1/H3/H5 通过，H6 首次应用，H7 新项）+ H6 应用 |
| [docs/sprint-4/runtime-context.md](docs/sprint-4/runtime-context.md) | 工具链基线 + §H7 CPU profile top（GC 主导 41-50%）+ §H5 mem lifecycle 分类表 |
| [docs/sprint-4/progress.md](docs/sprint-4/progress.md) | Trace Log + gate 状态 + H7 基线（Dev/QA 填） |

---

# dae — PROJECT_BRIEF (Sprint 5 追加)

> Sprint 5 切换主题至**技术债清理 + 测量精度升级**。**核心 = H8 首次应用**（bench harness deadline 化）+ 开采 Sprint 1-4 四次 deferred 的测试瘦身矿脉 + Sprint 4 OQ-S4-3 的 CPU 算法矿脉。
> 以下为 Sprint 5 增量。详细文档见 [docs/sprint-5/](docs/sprint-5/)。

## Sprint 5 目标 / Goals

- **T1（AI 批量测试瘦身，用户锁定）**：删除 commit #970(85a1fc3c,136) / 0486201e(55) / b7fb496d(15) 批量添加的冗余测试。方法论：`/memories/ai-test-pruning.md`（dae 实例）。test:src 从 1.03 降至 ~0.5。保留硬规则：helpers（9）/fuzz（6）/每模块 1-2 核心契约/原生 16/T3 目标。
- **T2（sniffHTTPHostHeader CPU 算法优化）**：来源 S4 H7 CPU profile（cum 16.85% / bytes.Index 9.95%，OQ-S4-3）。纯 CPU 算法（非分配驱动），verdict 须含 H7 CPU 维度。
- **T3（H8 首次应用：bench harness deadline 化）**：来源 S4 L14（bytes.Reader 无 deadline → 强制 async 路径，掩盖生产 TCP 真实分配）。把 `benchmark_test.go` 的 `bytes.NewReader` 替换为 deadline-supporting conn。
- **整体**：应用 H1-H8（H8 首次）+ 评估 H9；v5.0 可行性前置 gate（G1/G2 普适 + G3/G4 perf 专属条件性）。

## Sprint 5 非目标 / Out-of-Scope

- 长驻 reader goroutine（lifecycle 高风险，触 OQ-S4-1 读语义风险，需独立 lifecycle Sprint）
- ReassembleCryptos merged slice 预分配（<1pp，收益 marginal）
- T2 扩散到 tls.go/quic.go/sniffer.go 其他嗅探函数（YAGNI，只动 sniffHTTPHostHeader 路径）
- T3 动生产 sniffer.go 读路径（H8 是 harness 改进非生产代码改动）
- T1 碰原生 16 个测试（2023 年）或 helpers/fuzz
- 行为/API/config 变更、fork（quic-go/outbound）、eBPF C（tproxy.c）

## Sprint 5 blast_radius / task_sizing

| 项 | 值 |
|----|----|
| task_count | 3（T1→T2→T3 全串行） |
| strong_coupling | 1（T1/T3 sniffing 测试包编译耦合） |
| commit_budget | **5**（dag_layers=3 + strong_coupling=1 + bug_reserve=1，hard_cap=10） |
| topology | **sequential**（H9 评估：T1 删 sniffing 包测试 + T3 改 benchmark_test.go 同包，无法证明 target_files 互斥） |

## Sprint 5 验收标准 / Acceptance Criteria

1. `go vet/build/test -tags=trace ./...` 通过（T1 删除后 helper 链恢复驱动）
2. `go test -race -tags=trace ./component/sniffing/... ./control/...` 通过
3. `make ebpf-test` 本机 runs（PASS，H1）+ `make ebpf` EXIT=0
4. **deletion_protection_check（T1 专属）**：comm -12 交集为空（只删批量 commit 添加的，原生 16 绝不碰）
5. **cpu_profile_review（H7，T2 决定性）**：sniffHTTPHostHeader cum% < 16.85% + bytes.Index cum% < 9.95%（不可仅用 bench allocs 判，OQ-S5-1）
6. **h8_deadline_sync_verification（H8 首次，T3 决定性）**：3 个 SniffTcp bench 全用 deadline-supporting conn + pprof 确认走 deadline_sync_read 非 async
7. T1 test:src 比从 1.03 降至 ~0.5；T3 bench SniffTcp_* 趋近 deadline_sync 基线（5 而非 13）
8. 无行为/API/config 变更

## Sprint 5 第 7 节更新 / Phase Status（Sprint 5）

| 时间 | 阶段 | 负责人 | 状态 |
|------|------|--------|------|
| 2026-07-29 | Sprint 5 Planning（drift-check + 可行性预检 + plan + brief §7/§8） | Remy | ✅ 完成 |
| 2026-07-29 | Sprint 5 Dev（T1 测试瘦身 / T2 http.go CPU / T3 bench harness，全串行） | Dev | ✅ 完成（4 commits：`0e673fe7` / `1d1021eb` / `d3e5c4a2` / `828afae5`） |
| 2026-07-29 | Sprint 5 QA（gate + cpu_profile_review + h8_deadline_sync + L2 retry） | QA | ✅ PASS（升级自 CONDITIONAL via L2 retry，[docs/qa/qa-signoff-5.md](docs/qa/qa-signoff-5.md)，head_commit `722b123b`） |

> Sprint 1-4 已全部 QA 签署 PASS（见 [docs/qa/qa-signoff-{1,4}.md](docs/qa/)），其第 7 节状态保持历史记录。

## Sprint 5 第 8 节更新 / Handoff Context

### Producer → Dev（Sprint 5）
- 本文件 + [docs/sprint-5/plan.md](docs/sprint-5/plan.md)（task DAG + 可行性 gate + verifiable_gates + task_sizing + H1-H8 应用）。
- 基线 + 删除清单 + H7 CPU 证据 + bench harness 偏差定位：[docs/sprint-5/runtime-context.md](docs/sprint-5/runtime-context.md)（T1 统计 + T2 H7 基线 + T3 代码定位）。
- drift 依据：[docs/sprint-5/drift-check.md](docs/sprint-5/drift-check.md)（零技术 context drift / L1-L14 全规避 L9+L14 核心 / S4 Sprint+1 三候选全纳入 / fidelity 权威 git-log=0% ungated）。
- **Dev 必读**：① T1 方法论 `/memories/ai-test-pruning.md`（helper 链处理最易踩坑，go vet 驱动恢复）；② T2 ⚠️ 用户描述「bytes.Index 替代手写字节扫描」与实际不符（http.go 已用 bytes 原语），OQ-S5-1 已 reformulate 为减 rescan + 消 string 分配 + 跳 request line，若无可优化空间须诚实标 no-op；③ T3 OQ-S5-3 deadline conn 选型须 pprof 确认走 deadline 路径；④ 命令脚本化 tmp/*.sh（H3）；注释/commit 英文。
- 拓扑：**全串行 T1→T2→T3**（H9：T1/T3 sniffing 测试包编译耦合）。

### Dev → QA（Sprint 5）
- **改动文件清单**：108 测试删除 + 3 新集中 helper 文件（`control/{scripted_packet_conn,test_fixtures,dns_message}_test_helpers_test.go`）+ 3 恢复 bulk-infra 文件（udp_quic_initial_regression/udp_reuse_simulation/udp_sniffer_loss）+ `component/sniffing/http.go`(+45/-10) + `component/sniffing/benchmark_test.go`(+43/-3) + 恢复 `control/bpf_bug_verification_test.go`。
- **bench 前后要点**：T2 Extended -36% / NoHost -43% / bytes.Index cum 57.92%→8.66%；T3 HTTP ~12→5 / TLS ~12→6 / NotApplicable ~12→3（H8 收益闭环，非回归）。
- **H7 verdict**：PASS（bytes.Index cum 大降 + ns/op 绝对下降；GC 极低 2.12% 确认 CPU 算法非 alloc 驱动）。
- **已知限制（OQ）**：OQ-S5-1（T2 premise reformulate，闭环）/ OQ-S5-2（T1 helper 链 ~5 层，闭环）/ OQ-S5-3（T3 deadlineConn 选型，闭环）。
- **文档**：[docs/sprint-5/progress.md](docs/sprint-5/progress.md)（Trace Log + bench 基线）；commits `0e673fe7` / `1d1021eb` / `d3e5c4a2` / `828afae5`。

### QA → done（Sprint 5）
- **verdict = PASS**（升级自 CONDITIONAL，[docs/qa/qa-signoff-5.md](docs/qa/qa-signoff-5.md)，head_commit `722b123b`）：local_gate + ci_gate + manual_gate 全过（L2 retry 修复 ISSUE-1 后）；H5/H7/H8 决定性 gate 独立复现 Dev 数据。
- **L2 retry**：ISSUE-1（T1 误删 Makefile 引用的 `bpf_bug_verification_test.go`）→ commit `722b123b` 恢复 → `make ebpf-test` EXIT=0。commits_used 最终 = 5/5（bug_reserve 正确覆盖）。
- **L4 完成**（[docs/sprint-5/hill-climbing.md](docs/sprint-5/hill-climbing.md)）：新增 L15-L17；H8/H9 applied，H10 proposed；no-op 率连续 3 Sprint 为 0%。**Sprint 5 fully closed。** 见 [docs/sprint-5/done.md](docs/sprint-5/done.md)。

## Sprint 5 关键文档索引

| 文档 | 用途 |
|------|------|
| [docs/sprint-5/plan.md](docs/sprint-5/plan.md) | task DAG（含可行性 gate）/ verifiable_gates（+cpu_profile_review +h8_deadline_sync +deletion_protection）/ task_sizing |
| [docs/sprint-5/drift-check.md](docs/sprint-5/drift-check.md) | 4 项 drift + Evals（H1/H3/H5 通过，H6/H7 持续，H8 首次应用）+ backlog 应用清单 |
| [docs/sprint-5/runtime-context.md](docs/sprint-5/runtime-context.md) | T1 测试统计 + 删除/保留清单 + T2 H7 CPU 庺线 + T3 bench harness 偏差定位 |
| [docs/sprint-5/progress.md](docs/sprint-5/progress.md) | Trace Log + gate 状态（Dev/QA 填） |

---

# dae — PROJECT_BRIEF (Sprint 6 追加)

> Sprint 6 是**首次验证型 Sprint**（stability_hardening_allowed）。对 Sprint 5 之后的 23 个游离 commit（未编排工作）补齐权威验证基线。详细文档见 [docs/sprint-6/](docs/sprint-6/)。

## Sprint 6 目标 / Goals

- **T1（权威验证基线）**：23 个游离 commit（722b123b..1ddfd8fb）含巨型文件拆分 + 5 bug fix + perf + fork bump，补齐 race/ebpf/bench 权威验证。scenario (a) 全过=基线确认 / (b) 发现回归=捕获修复。

## Sprint 6 非目标 / Out-of-Scope

- 新协议 / 新 feature；巨型文件拆分（已被游离 commit 做了，不重做）；eBPF C 改动（tproxy.c）；config 语言变更；fork（quic-go/outbound）改动；语义等价重构（非稳定性主题）。

## Sprint 6 第 7 节 / Phase Status（Sprint 6）

| 时间 | 阶段 | 负责人 | 状态 |
|------|------|--------|------|
| 2026-08-04 | Sprint 6 Planning（drift-check + 23 游离 commit 分析 + plan） | Remy | ✅ 完成 |
| 2026-08-04 | Sprint 6 Dev（T1 权威验证 + 回归修复） | Dev | ✅ 完成（10/10 gate pass, 0 回归, commit 149b3ce9 docs only） |
| 2026-08-04 | Sprint 6 QA（gate 复核 + bench H8 抽检） | Ivy | ✅ PASS（[docs/qa/qa-signoff-6.md](docs/qa/qa-signoff-6.md)，head_commit 149b3ce9） |

> Sprint 1-5 已全部 fully closed（见各自 done.md）。

## Sprint 6 第 8 节 / Handoff Context

### Dev → QA（Sprint 6）
- **改动文件**：0 源码改动（commit 149b3ce9 纯 docs：docs/sprint-6/{plan,progress,drift-check,runtime-context}.md, 466 ins）。
- **gate 结果**：10/10 pass（race rc=0 50.5s / ebpf-test rc=0 13.8s, 23 用例 / bench H8 全匹配 SniffTcp HTTP=5/TLS=6/NotApp=3 / ebpf-lint+sync rc=0 / make dae validate rc=0）。
- **已知限制**：4 项环境障碍（submodule init / Makefile .gitmodules.d.mk 上游 bug OQ-S6-4 / checkpatch CRLF / C 源码 autocrlf）均非代码回归。

### QA → done（Sprint 6）
- **verdict = PASS**（[docs/qa/qa-signoff-6.md](docs/qa/qa-signoff-6.md)，head_commit `149b3ce9`）：local_gate 4/4 + ci_gate 4/4 + manual_gate 3/3；scenario (a) 命中；commits_used=1/3。
- **L4 完成**（[docs/sprint-6/hill-climbing.md](docs/sprint-6/hill-climbing.md)）：新增 L19（WSL CRLF 污染清理）/ L20（commits 计数）；H11（CRLF 检查）/ H12（fork 验证 harness）proposed；首次验证型 Sprint + 首次零代码 commit。**Sprint 6 fully closed。** 见 [docs/sprint-6/done.md](docs/sprint-6/done.md)。

## Sprint 6 关键文档索引

| 文档 | 用途 |
|------|------|
| [docs/sprint-6/plan.md](docs/sprint-6/plan.md) | task DAG T1 + verifiable_gates + constraint_policy(stability_hardening_allowed) |
| [docs/sprint-6/drift-check.md](docs/sprint-6/drift-check.md) | §0 既成事实基线（23 游离 commit）+ 4 项 drift |
| [docs/sprint-6/progress.md](docs/sprint-6/progress.md) | Trace Log + L2 Verification（l2_verified_sha=149b3ce9）|
| [docs/sprint-6/hill-climbing.md](docs/sprint-6/hill-climbing.md) | L4 报告 + L19/L20 + H11/H12 |
