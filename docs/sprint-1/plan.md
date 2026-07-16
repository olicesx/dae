# Sprint 1 — dae 只读审阅执行计划

> 所有任务均为**只读审阅**，产出发现清单，不修改源码。任务按模块边界切分，**可并行派只读子 agent 执行**。每个子 agent prompt ≤ 5K tokens，大上下文让 agent 自行 `list_dir`/`read_file`。

## 审阅单元总览

| 任务 | 审阅对象 | 维度 | 并行性 |
|---|---|---|---|
| T1 | control/ 编排核心 | D1 D2 D6 | 独立 |
| T2 | control/ DNS 子系统 | D1 D2 D6 | 独立 |
| T3 | control/ TCP relay | D2 D5 D6 | 独立 |
| T4 | control/ UDP relay | D2 D5 D6 | 独立 |
| T5 | control/ BPF 管理与生命周期 | D2 D3 D6 | 独立 |
| T6 | control/ 拨号与路由匹配 | D1 D2 D6 | 独立 |
| T7 | control/kern/ eBPF C | D3 D5 | 独立 |
| T8 | component/outbound | D1 D2 D6 | 独立 |
| T9 | component/dns | D1 D5 | 独立 |
| T10 | component/routing | D1 D5 | 独立 |
| T11 | component/sniffing | D5 D6 | 独立 |
| T12 | config/ | D5 D6 | 独立 |
| T13 | 跨切面：并发模式全局审计 | D2 | 独立（grep 驱动） |
| T14 | 跨切面：错误处理与资源泄漏 | D6 | 独立（grep 驱动） |
| T15 | 跨切面：依赖与构建 | D7 | 独立 |

> T13/T14 为跨模块横切审计，建议在各模块任务（T1-T12）完成后执行，以避免与模块任务重复读取。

---

## 模块审阅任务

### T1 — control/ 编排核心
- **对象**：`control/control.go`、`control/control_plane.go`、`control/control_plane_core.go`、`control/control_plane_drain.go`、`control/generation_state.go`
- **维度**：D1 职责划分 / D2 并发安全 / D6 资源生命周期
- **检查点**：ControlPlane 是否上帝对象；stop/done/ready channel 生命周期；drain 路径是否完整释放；reload 时旧 plane 退出与新 plane 启动竞态
- **预计读**：上述 5 文件 + 关联 test（`control_plane_*_test.go`、`control_plane_drain_test.go`）

### T2 — control/ DNS 子系统
- **对象**：`control/dns.go`、`dns_control.go`、`dns_control_optimistic.go`、`dns_cache.go`、`dns_listener.go`、`dns_runtime.go`、`dns_utils.go`、`dns_preference_wait.go`、`runtime_dns_accounting.go`
- **维度**：D1 与 `component/dns` 职责重叠 / D2 缓存并发 / D6 连接池与 janitor
- **检查点**：DNS 缓存 COW 与 LRU 一致性；singleflight 失败缓存；conn pool 释放；optimistic 更新竞态；负缓存 TTL
- **预计读**：上述文件 + `dns_cache_*_test.go`、`dns_concurrency_test.go`、`dns_singleflight_test.go`

### T3 — control/ TCP relay
- **对象**：`control/tcp.go`、`tcp_copy_engine.go`、`tcp_copy_linux.go`、`tcp_copy_other.go`、`tcp_copy_gather_linux.go`、`tcp_copy_gather_other.go`、`tcp_relay_core.go`、`tcp_relay_capabilities.go`、`tcp_sniff_policy.go`、`tcp_offload_other.go`
- **维度**：D2 并发 / D5 build tag 对完整性 / D6 goroutine 与 conn 泄漏
- **检查点**：copy goroutine 退出路径；零拷贝/gather 路径正确性；sniff policy 与 copy 协调；linux/other 文件对称性
- **预计读**：上述文件 + `tcp_copy_*_test.go`、`tcp_test.go`

### T4 — control/ UDP relay
- **对象**：`control/udp.go`、`udp_flow.go`、`udp_lifecycle.go`、`udp_task_pool.go`、`udp_unordered_task_runner.go`、`udp_endpoint_pool.go`、`udp_ingress_batch.go`、`udp_profile.go`、`udp_conn_state_tracker.go`、`raw_udp_linux.go`、`raw_udp_other.go`、`packet_sniffer_pool.go`
- **维度**：D2 并发 / D5 复杂度与重复 / D6 pool 与 endpoint 释放
- **检查点**：UDP 无序处理正确性；endpoint pool janitor；conn state tracker 竞态；task pool 满载处理
- **预计读**：上述文件 + `udp_*_test.go`、`raw_udp_linux_test.go`、`packet_sniffer_pool_test.go`

### T5 — control/ BPF 管理与生命周期
- **对象**：`control/bpf_utils.go`、`bpf_stub.go`、`bpf_subobjects.go`、`bpf_purge.go`、`netkit_linux.go`、`netkit_netlink.go`、`datapath_janitor.go`、`sysctl.go`、`netns_utils.go`
- **维度**：D2 map 更新竞态 / D3 map 生命周期与 FD / D6 泄漏
- **检查点**：map 加载/卸载时序；reload purge 完整性；batch delete 边界；netlink 错误处理；netns 切换隔离
- **预计读**：上述文件 + `bpf_utils_*_test.go`、`bpf_load_test.go`、`bpf_subobjects.go`

### T6 — control/ 拨号与路由匹配
- **对象**：`control/dial.go`、`routing_matcher_builder.go`、`routing_matcher_userspace.go`、`domain_routing_tracker.go`、`anyfrom_pool.go`、`node_latency.go`、`connectivity.go`
- **维度**：D1 与 component/routing 边界 / D2 池并发 / D6 拨号失败处理
- **检查点**：dial family fallback 正确性；routing matcher 构建幂等；domain tracker 并发更新；anyfrom 池竞态；latency 探测超时
- **预计读**：上述文件 + `dial_family_fallback_test.go`、`route_dial_family_fallback_test.go`、`domain_routing_tracker_test.go`

### T7 — control/kern/ eBPF C 程序
- **对象**：`control/kern/tproxy.c`、`control/kern/ebpf_sync_defs.h`、`control/kern/headers/`、`control/kern/tests/`
- **维度**：D3 Go↔C 结构同步 / D5 clang-format 与 checkpatch
- **检查点**：结构与 Go 侧 `bpf_bpfel.go`/`consts` 同步；map 访问边界检查；verifier 友好性；kernel 5.4-6.x 兼容；注释全英文
- **预计读**：`tproxy.c`（分段）、`ebpf_sync_defs.h`、`headers/*`

### T8 — component/outbound
- **对象**：`component/outbound/dialer_group.go`、`dialer_selection_policy.go`、`outbound.go`、`filter.go`、`dialer/`（注册与各协议）
- **维度**：D1 边界 / D2 选择策略并发 / D6 拨号器生命周期
- **检查点**：dialer group 选择算法；health check 与切换竞态；filter 逻辑；dialer 注册机制
- **预计读**：上述文件 + `dialer_group_test.go`、`dialer_selection_policy_test.go`

### T9 — component/dns
- **对象**：`component/dns/dns.go`、`upstream.go`、`request_routing.go`、`response_routing.go`、`routing_program.go`、`request_rule_split.go`、`function_parser.go`
- **维度**：D1 与 control/dns 重叠 / D5 解析逻辑复杂度
- **检查点**：request/response routing 分工；function_parser 健壮性；upstream 容错；rule split 正确性
- **预计读**：上述文件 + `routing_program_test.go`、`fallback_contract_test.go`、`upstream_test.go`

### T10 — component/routing
- **对象**：`component/routing/domain_matcher.go`、`ir.go`、`normalize.go`、`optimizer.go`、`matcher_builder.go`、`function_parser.go`、`domain_matcher/`
- **维度**：D1 与 control/routing_matcher 边界 / D5 IR 与 optimizer 正确性
- **检查点**：IR 设计合理性；optimizer 是否破坏语义；domain matcher（trie/ahocorasick）性能与正确性
- **预计读**：上述文件 + `normalize_test.go`、`optimizer_contract_test.go`

### T11 — component/sniffing
- **对象**：`component/sniffing/sniffing.go`、`sniffer.go`、`conn_sniffer.go`、`tls.go`、`http.go`、`quic.go`
- **维度**：D5 解析健壮性 / D6 内存与读取边界
- **检查点**：协议解析边界检查（OOB/畸形包）；QUIC initial 解析；conn sniffer relay 内存；fuzz 覆盖
- **预计读**：上述文件 + `tls_fuzz_test.go`、`quic_fuzz_test.go`、`http_fuzz_test.go`、`benchmark_test.go`

### T12 — config/
- **对象**：`config/config.go`、`parser.go`、`decode.go`、`marshal.go`、`outline.go`、`desc.go`、`patch.go`、`config_merger.go`、`bootstrap_resolver.go`
- **维度**：D5 解析健壮性 / D6 合并冲突处理
- **检查点**：parser 对畸形输入容错；merger 冲突解决；bootstrap resolver 可靠性；patch 幂等
- **预计读**：上述文件 + `decode_test.go`、`outline_test.go`、`bootstrap_resolver_test.go`

---

## 跨切面审计任务（建议 T1-T12 后执行）

### T13 — 并发模式全局审计
- **方法**：`grep_search` 统计 `sync.Map`、`sync.RWMutex`、`singleflight`、`atomic.`、`close(`、`<-` stop channel 全仓用法
- **检查点**：check-then-act 竞态；锁内阻塞调用；channel 多发送者关闭；atomic 误用为同步
- **预计读**：grep 结果 + 抽样定位文件

### T14 — 错误处理与资源泄漏审计
- **方法**：`grep_search` 统计 `err ==`、`_ =`（忽略 error）、`defer`、`Close()`、`go func`、`context.WithCancel/Timeout`
- **检查点**：error 忽略；defer 在循环；goroutine 无退出路径；conn 未 Close；context 未取消
- **预计读**：grep 结果 + 抽样定位文件

### T15 — 依赖与构建审计
- **方法**：读 `go.mod` 全量、`Makefile`、`.github/workflows/`、`.clang-format`、`pre-commit-config`
- **检查点**：fork replace 必要性；版本陈旧/CVE；CI 矩阵与 Makefile 目标一致；ebpf-lint/sync-check 配置
- **预计读**：上述文件 + `go.sum` 抽样

---

## 验收标准

每个任务交付**发现清单**，格式：

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P0/P1/P2/P3 | `path/file.go:L` | … | … |

- **P0** 致命：数据竞争导致崩溃 / 资源确定性泄漏 / 安全漏洞
- **P1** 严重：高频路径并发隐患 / map 生命周期错误 / 大范围职责混乱
- **P2** 一般：错误处理缺陷 / 测试盲区 / 中等重复
- **P3** 建议：命名/可读性/微优化/文档

每个任务至少覆盖其标注维度的全部检查点，无遗漏项需在发现清单中说明"已检查，未发现问题"。

## 本 Sprint 不做什么

- ❌ 不修改任何源代码（包括"顺手修复"小问题）
- ❌ 不深入第三方 fork 库内部实现
- ❌ 不做真实内核性能压测
- ❌ 不重写测试，仅评估现有测试质量
- ❌ 不新增功能设计文档
