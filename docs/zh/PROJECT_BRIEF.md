# dae 架构与代码质量审阅 — PROJECT_BRIEF

> **性质说明**：本项目 `dae` 为已有成熟开源项目（Go 1.26 + eBPF 透明代理），本次任务为**只读架构与代码质量审阅**，非功能开发。因此本简报采用聚焦审阅的精简结构，不套用功能开发的 14 章模板。**全程不修改任何源代码**，仅产出发现报告。

---

## 1. 项目现状概述

`dae` 是基于 Linux 内核 eBPF 的高性能透明代理，通过在数据面进行流量分流，使直连流量绕过用户态代理转发以实现近乎零损耗。核心语言 Go 1.26，关键依赖 `cilium/ebpf v0.20.0`、`olicesx/outbound`(fork)、`olicesx/quic-go`(fork)、`miekg/dns`、`cobra`。`control/` 包是系统的中枢，但其职责边界异常庞大，单包内混合了编排、DNS、TCP/UDP relay、BPF 生命周期、拨号、路由匹配、运维清理等多重职责，是本次审阅的重点关切区域。

## 2. 审阅目标与范围

| 项 | 内容 |
|---|---|
| **目标** | 对 dae 代码库进行系统性只读审阅，识别架构耦合、并发风险、eBPF 交互隐患、资源泄漏、测试盲区，输出分级发现清单（P0-P3），为后续（由 Dev 执行的）改进提供依据 |
| **范围** | Go 控制面全量 + eBPF C 程序 + 配置解析 + 构建与依赖 |
| **交付物** | `docs/sprint-1/plan.md`（任务拆解）、`docs/sprint-1/progress.md`（进度跟踪）、各审阅单元的发现清单 |
| **约束** | 只读。所有发现以 Issue 形式记录交 Dev 处理，Remy 绝不写/改源码 |

## 3. 审阅维度清单

| # | 维度 | 关注点概述 |
|---|---|---|
| D1 | **架构耦合与职责划分** | `control/` 包膨胀、模块边界、循环依赖、上帝对象 |
| D2 | **并发安全** | `sync.Map`/`RWMutex`/`singleflight`/channel/atomic 用法正确性、数据竞争、锁粒度 |
| D3 | **eBPF-Go 交互与 map 生命周期** | map 更新一致性、FD 泄漏、reload 时 map 重建、Go↔C 结构同步、内核版本兼容 |
| D4 | **测试覆盖与质量** | 测试盲区、并发测试（race）、bench 覆盖、mock 边界、flaky 风险 |
| D5 | **代码质量** | 复杂度、重复代码、命名一致性、死代码、build tag 正确性 |
| D6 | **错误处理与资源泄漏** | error wrap/忽略、defer/Close、context 取消传播、goroutine 泄漏、conn pool 释放 |
| D7 | **依赖管理与版本风险** | fork 依赖维护成本、go.mod 版本、replace 指令、CI 矩阵、Makefile 正确性 |

## 4. 各维度具体检查点

### D1 架构耦合与职责划分
- `control/` 单包文件数（130+，核心实现 50+）是否应拆分为子包（dns/tcp/udp/bpf/dial/routing）
- `ControlPlane` 是否为上帝对象（聚合过多职责）
- `component/dns` 与 `control/dns*.go` 的职责重叠与重复
- `routing` 逻辑分散于 `component/routing` + `control/routing_matcher_*` + `config`，边界是否清晰
- 跨包循环依赖风险

### D2 并发安全
- `sync.Map` 的 Load+Store 非原子组合是否存在 check-then-act 竞态
- `RWMutex` 写锁持锁期间是否调用可能阻塞/重入的逻辑
- `singleflight` 失败结果是否被错误缓存
- channel 关闭与多发送者模式（stop/done/ready）是否安全
- atomic 操作是否用作同步原语外的"优化"导致可见性问题
- reload 路径下的并发 map 重建竞态

### D3 eBPF-Go 交互与 map 生命周期
- `bpf_utils.go`/`bpf_subobjects.go`/`netkit_*.go` 的 map 加载/卸载时序
- reload 时旧 map 是否完整 purge（`bpf_purge.go`）
- Go 结构体与 `ebpf_sync_defs.h`/`tproxy.c` 定义是否同步（`make ebpf-sync-check`）
- map 批量删除（`bpf_utils_batch_delete_all_test` 暗示）的边界条件
- FD 泄漏、`LoadAndAssign` 错误处理
- 内核版本/特性探测（build tag `linux`/`other`）正确性

### D4 测试覆盖与质量
- 核心非 test 文件中哪些完全没有对应 test（盲区）
- 并发热点是否有 `*_race_test.go` / `-race` 覆盖
- eBPF 路径的 mock 是否掩盖真实行为（`bpf_stub.go`）
- bench（`dns_cache_bench`、`runtime_stats_bench`、`tcp_copy_engine_bench`）是否覆盖热点
- flaky 测试风险（依赖时序/网络/真实内核的 test）

### D5 代码质量
- 超长函数 / 高圈复杂度热点
- build tag 文件对（`*_linux.go`/`*_other.go`）是否完整对应
- `*_generated`/手写代码混淆
- 重复逻辑（如多处 dial family fallback、routing 构建重复）

### D6 错误处理与资源泄漏
- `err == nil` 后的 nil 解引用风险
- goroutine 启动后是否有明确退出路径（context/channel）
- conn pool（`udp_endpoint_pool`/`dns_conn_pool`/`packet_sniffer_pool`）的释放与 janitor
- defer 在循环中的资源累积
- context 取消是否在所有阻塞 I/O 处传播

### D7 依赖管理与版本风险
- fork 依赖（`olicesx/outbound`、`olicesx/quic-go`）的上游同步策略与维护成本
- `replace` 指令清单与必要性
- go.mod 版本是否过旧/有已知 CVE
- Makefile 目标（`dae`/`ebpf`/`ebpf-lint`/`ebpf-sync-check`）正确性与 CI 一致性

## 5. 不审阅的范围（Out of Scope）

| 项 | 原因 |
|---|---|
| 任何源代码修改 | 任务明确只读，改进交 Dev 执行 |
| 新功能设计 / PRD | 本次不涉及功能规划 |
| 性能压测实测 | 需真实内核环境，超出静态审阅范围 |
| `docs/en/` 文档内容校对 | 非代码质量范畴 |
| 第三方 fork 库的内部实现 | 仅评估依赖关系与版本风险，不深入 fork 源码 |
| UI / 前端 | dae 为 CLI/系统组件，无前端 |

## 6. 审阅执行与验收

详见 `docs/sprint-1/plan.md`。每个审阅单元（共 15 个，按模块边界切分可并行）产出**发现清单**，每条发现含：严重度（P0 致命 / P1 严重 / P2 一般 / P3 建议）、`文件:行号`、问题描述、改进建议。所有发现汇总后由 Remy 整理为 Issue 交 Dev。
