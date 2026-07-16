# dae 架构与代码质量审阅报告

> Sprint 1 · 只读审阅 · 2026-07-03
> 范围：control/ · component/ · config/ · control/kern/ · 跨切面
> 方法：6 个只读审阅单元并行执行，不修改任何源码

---

## 1. 执行摘要

dae 是一个工程质量**明显高于平均**的 eBPF 透明代理项目。核心数据路径（DNS 缓存、TCP relay、UDP endpoint pool）的并发设计扎实，eBPF C 程序边界检查严密、verifier 友好，Go↔C 结构同步有双向保证，sniffing 三协议均有 fuzz 覆盖。

**未发现 P0 致命问题**（数据竞争致崩溃 / 确定性资源泄漏 / 安全漏洞）。

主要改进空间集中在三个层面：
1. **架构层**：`ControlPlane` 上帝对象，reload 正确性依赖隐式跨层调用顺序契约。
2. **正确性层**：`routing optimizer` 取反规则合并存在语义错误（OR 误为 AND）。
3. **供应链与治理层**：核心依赖 fork 到个人命名空间、CI 未跑 ebpf-sync-check、GOEXPERIMENT 不一致。

---

## 2. 发现统计

| 模块 | 文件 | P0 | P1 | P2 | P3 | 合计 |
|---|---|---|---|---|---|---|
| control/ 编排核心 | [findings-control-core.md](findings-control-core.md) | 0 | 1 | 2 | 7 | 10 |
| control/ 数据路径(DNS/TCP/UDP) | [findings-control-datapath.md](findings-control-datapath.md) | 0 | 0 | 5 | 7 | 12 |
| control/kern/ eBPF C | [findings-ebpf-c.md](findings-ebpf-c.md) | 0 | 0 | 4 | 5 | 9 |
| component/ | [findings-component.md](findings-component.md) | 0 | 1 | 3 | 4 | 8 |
| config/ | [findings-config.md](findings-config.md) | 0 | 0 | 3 | 4 | 7 |
| 跨切面(并发/错误/依赖) | [findings-crosscutting.md](findings-crosscutting.md) | 0 | 1 | 9 | 11 | 21 |
| **合计** | | **0** | **3** | **26** | **38** | **67** |

---

## 3. P1 严重问题（建议优先处理）

### P1-1 · `ControlPlane` 上帝对象
- **位置**：[control/control_plane.go:46-118](../../control/control_plane.go#L46-L118)
- **现象**：单个 struct/单文件聚合 DNS 路由、负缓存、拨号快照、监听 socket、datapath janitor 等十余类异质状态。
- **影响**：reload 正确性高度依赖 `MarkRetired`→健康检查、`EjectBpf`→`InjectBpf`、LPM slot 移交等**跨层调用顺序契约**，内部有标志防重入，但缺状态机封装/断言，演进时易引入回归。
- **建议**：代码已有 `controlPlaneDatapathJanitor`/`controlPlaneDNSRuntime` 嵌入拆分先例，可沿此模式继续按职责域拆分，并为 reload 流程引入显式状态机 + 不变式断言。

### P1-2 · `routing optimizer` 取反规则合并语义错误
- **位置**：[component/routing/optimizer.go:82-106](../../component/routing/optimizer.go#L82-L106)
- **现象**：`MergeAndSortRulesOptimizer` 合并取反(`Not=true`)单函数规则时把 OR 语义变成 AND：`!f(a)->X` ∪ `!f(b)->X` 合并为 `!f(a,b)->X`，在"单边匹配"场景路由结果不同。
- **影响**：路由结果与用户规则语义不一致，属功能性正确性缺陷。
- **建议**：合并条件增加 `!Not` 守卫，并补充契约测试覆盖取反合并场景。

### P1-3 · 核心依赖 fork 治理风险
- **位置**：[go.mod](../../go.mod)（replace 指令）、[findings-crosscutting.md](findings-crosscutting.md)
- **现象**：`quic-go` fork 到 `olicesx` 个人命名空间；`outbound` require/replace 版本号语义不一致。
- **影响**：供应链可追踪性、后续升级与安全响应难度。
- **建议**：核实 fork 必要性与上游回馈计划；统一 require/replace 版本语义；在文档中记录 fork 原因。

---

## 4. P2 问题汇总（按主题归类）

### 4.1 并发与资源生命周期
- **DialerGroup.Close() 竞态**：[component/outbound](../../component/outbound/) — Close 完全绕过 `selectionStateMu`，与 `SetSelectionPolicy()` 存在 unregister 竞态（模块审阅未覆盖此路径）。
- **closeTail 泄漏**：[control/control_plane.go:3572](../../control/control_plane.go#L3572) — bpfEjected 路径嵌套 goroutine，`netlink.FilterDel` 永久阻塞时泄漏（代码注释已承认）。
- **domainRoutingTracker 锁内 BPF 操作**：[control/domain_routing_tracker.go:160](../../control/domain_routing_tracker.go#L160) — 持 `t.mu` 执行 BPF batch，旧内核退化为逐条循环，DNS 高并发下成热点。
- **upstream 重复初始化**：[component/dns/upstream.go:200](../../component/dns/upstream.go#L200) — `GetUpstream` 并发初始化产生重复指针与重复回调。
- **sniffer goroutine 泄漏**：[component/sniffing/sniffer.go:150](../../component/sniffing/sniffer.go#L150) — 异步读 goroutine 在 `SetReadDeadline` 不支持时超时即泄漏至连接关闭。
- **UdpTaskPool overflow 无上限** + convoy panic 恢复误删新队列：[control/udp_task_pool.go](../../control/udp_task_pool.go)。

### 4.2 正确性
- **DNS NXDOMAIN/SERVFAIL 不缓存**：[control/dns_control.go:1530](../../control/dns_control.go#L1530) — 叠加 singleflight 失败不缓存，重复失败域名每次回源。
- **TCP eBPF offload 死代码**：[control/tcp.go](../../control/tcp.go) — `tryOffloadTCPRelay` 仅 `!linux` 定义且零调用，offload 分支桩化未实现，无对称 linux 文件。
- **eBPF `pid_is_control_plane` 硬编码 mark 位**：`0x100` 未同步 Go 常量。
- **eBPF `route()` 的 `active_rules_len` 无下限检查**：len==0 时全流量 SHOT，需确认产品语义。

### 4.3 错误处理与可观测性
- **5 处生产 `recover()` 全用 `%v` 无堆栈**：排查困难。
- **config include 空匹配静默丢弃**：[config/config_merger.go](../../config/config_merger.go) — 拼错文件名不报错。
- **config 合并语义未文档化**：隐式"标量覆盖、切片累积"。

### 4.4 构建与 CI
- **`make ebpf-sync-check` 未在任何 CI 执行**：Go↔C 结构漂移无门禁。
- **CI 各 job GOEXPERIMENT 不一致**：测试与生产行为差异。
- **`cookie_pid_map` 无 userspace janitor 兜底清理**。

---

## 5. 架构亮点（值得保持）

| 领域 | 亮点 |
|---|---|
| Go↔C 同步 | bpf2go + ebpf_sync_spec.json 双向保证，逐字节匹配；全文件 CJK 扫描为空，注释全英文合规 |
| eBPF 边界检查 | 严格 `>data_end` 模式、`ihl<5` 拦截、扩展头循环上限 |
| verifier 友好 | PERCPU scratch map 规避栈深度、bpf_loop 替代 tail_call |
| DNS 缓存 | COW + atomic 快照、LRU 淘汰、负缓存 |
| TCP relay | relayCore 双向解阻塞设计 |
| UDP endpoint pool | 分片 janitor + `defer FinalizeRelease` 防死锁 |
| sniffing | Locator 抽象 + 处处 `len<boundary` 守卫；TLS/QUIC/HTTP fuzz 齐全 |
| 测试体系 | unit/bench/fuzz/race/integration 多层次覆盖 |

---

## 6. 改进建议优先级

| 优先级 | 行动 | 工作量 |
|---|---|---|
| 🔴 高 | P1-2 routing optimizer Not 合并语义修复 + 契约测试 | 小（单点修复） |
| 🔴 高 | CI 接入 `ebpf-sync-check` + 统一 GOEXPERIMENT | 小（CI 配置） |
| 🟡 中 | P1-1 ControlPlane 沿嵌入模式继续拆分 + reload 状态机 | 大（渐进重构） |
| 🟡 中 | 4.1 并发竞态项逐个修复 + 补 race 测试 | 中 |
| 🟡 中 | DNS 失败缓存（NXDOMAIN/SERVFAIL + singleflight） | 中 |
| 🟢 低 | P1-3 fork 治理文档化 | 小 |
| 🟢 低 | TCP offload 死代码清理或补实现 | 小 |
| 🟢 低 | recover 补堆栈、config 合并语义文档化 | 小 |

---

## 7. 审阅边界（本次未覆盖）

- ❌ 未深入第三方 fork 库（quic-go/outbound）内部实现
- ❌ 未做真实内核性能压测
- ❌ 未重写/新增测试，仅评估现有测试质量
- ❌ 未修改任何源码（用户要求仅出报告）

## 8. 产出文件索引

| 文件 | 内容 |
|---|---|
| [PROJECT_BRIEF.md](../../PROJECT_BRIEF.md) | 审阅目标、维度、范围 |
| [plan.md](plan.md) | 15 个审阅任务执行计划 |
| [progress.md](progress.md) | 任务进度跟踪 |
| findings-control-core.md | T1/T5/T6 发现清单 |
| findings-control-datapath.md | T2/T3/T4 发现清单 |
| findings-ebpf-c.md | T7 发现清单 |
| findings-component.md | T8-T11 发现清单 |
| findings-config.md | T12 发现清单 |
| findings-crosscutting.md | T13-T15 发现清单 |
| REVIEW-REPORT.md | 本汇总报告 |
