---
project: dae
sprint: 1
sprint_theme: "Semantic-preserving code slimming & runtime-overhead reduction / 语义不变的代码精简优化"
content_language: bilingual
content_language_source: inferred
model_context_window: 1000000
model_context_window_source: default
current_phase: planning
branch: kdae
last_updated: 2026-07-29
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
