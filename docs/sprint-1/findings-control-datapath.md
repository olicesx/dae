# T2 + T3 + T4 — control/ 数据路径只读审阅发现清单

> 审阅范围：control/ DNS 子系统（T2）、TCP relay（T3）、UDP relay（T4）。
> 审阅方式：只读，未修改任何源码。
> 维度：D1 职责划分 / D2 并发安全 / D5 build tag 对称性 / D6 资源生命周期。

## 发现汇总

| 严重度 | 数量 |
|---|---|
| P0 致命 | 0 |
| P1 严重 | 0 |
| P2 一般 | 5 |
| P3 建议 | 7 |

> 未发现 P0/P1。最严重为 P2：TCP offload 死代码、NXDOMAIN 不缓存、UdpTaskPool overflow 无上限、convoy panic 误删。所有检查点已覆盖，详见下表与“检查点逐项核验”。

## 发现明细

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P2 | [control/tcp_offload_other.go:11](control/tcp_offload_other.go#L11)、[control/tcp.go:252](control/tcp.go#L252) | **TCP eBPF offload 为未完成死代码**。`tryOffloadTCPRelay` 仅在 `//go:build !linux` 下定义，且**全仓无任何调用方**（grep 仅命中定义本身）。同时 [tcp.go](control/tcp.go) 中 `offloaded := false` 后紧接 `if offloaded { return nil }`（[L252](control/tcp.go#L252)/[L262](control/tcp.go#L262)），`offloaded` 永远为 false，`buildTCPLinkLogFields` 的 `ebpf_offload` 分支也永不触发。整个 offload 特性处于“桩化但未实现”状态，且无 `tcp_offload_linux.go` 对称实现，违反 build tag 对称预期。 | 要么补齐 linux 实现 + 调用点，要么删除 `tcp_offload_other.go` 及 tcp.go 中 offload 相关死分支，避免误导后续维护者。 |
| P2 | [control/dns_control.go:1530](control/dns_control.go#L1530) | **NXDOMAIN/SERVFAIL 响应不缓存（负缓存缺失）**。`NormalizeAndCacheDnsResp_` 在 `msg.Rcode != RcodeSuccess` 时直接 `return nil`，因此 NXDOMAIN（Rcode 3）与 SERVFAIL 完全不入缓存。对同一不存在域名的重复查询会每次回源到上游，放大上游压力，尤其在高频解析失败场景（D6 负缓存 TTL 检查点）。注意：NODATA（Rcode=Success 但 Answer 为空）会被缓存（走 `minFirefoxCacheTtl`），仅错误码响应被排除。 | 对 NXDOMAIN 引入受控的负缓存 TTL（如 `minFirefoxCacheTtl` 或单独的 `negativeCacheTtl`，可配置上限），SERVFAIL 可保持不缓存（避免缓存临时故障）。 |
| P2 | [control/udp_task_pool.go:82](control/udp_task_pool.go#L82)、[control/udp_task_pool.go:66](control/udp_task_pool.go#L66) | **UdpTaskPool overflow 模式下 overflow 切片无上限增长**。`enqueue` 在 per-key channel 饱和后切换到 overflow 模式并 `append`；`popOverflowTask` 仅在排空到 0 或低于 `cap/4` 时缩容。当某 hot-key 的入队速率持续 > convoy 排空速率（convoy 先排 channel 再排 overflow，[L131](control/udp_task_pool.go#L131)），channel 恒满，overflow 切片可无限增长，恶意/病理流量下存在内存放大风险（D6 pool 满载处理）。 | 为 overflow 设置硬上限（如 `UdpTaskQueueLength` 的 N 倍），超限后丢弃最旧任务并计数告警，而非无限 append。 |
| P2 | [control/udp_task_pool.go:153](control/udp_task_pool.go#L153) | **convoy panic 恢复路径可能误删新队列**。`convoy()` 的 `recover` 中执行 `q.p.queues.Delete(q.key)` 但未校验 map 中当前值是否仍是 `q`。若 panic 发生时该 key 已被 idle-GC 删除并被新 `acquireQueue` 重建为另一个 `*UdpTaskQueue`，此处的无条件 `Delete` 会误删新队列，导致新 convoy 的任务丢失（D2）。 | 改为 `q.p.queues.CompareAndDelete(q.key, q)`，仅当 map 中仍是本队列时才删除。 |
| P2 | [control/dns_control.go:2259](control/dns_control.go#L2259) | **singleflight 失败不缓存、不防穿透**。`HandleWithResponseWriter_` 在 `c.sf.Do` 返回 err 时直接向上返回，无失败结果缓存。叠加上一条 NXDOMAIN 不缓存，对持续失败的域名，singleflight 只能合并“同一时刻”的并发，但跨时刻的重复失败仍每次回源（D2/D6）。 | 考虑对确定性的上游错误（如 REFUSED）做短 TTL 的失败缓存；至少为 NXDOMAIN 提供负缓存（见上）。 |
| P3 | [control/dns.go:1](control/dns.go)、[control/dns_control.go](control/dns_control.go) | **control/dns 与 component/dns 命名易混但职责实际分离**。control/dns.go 混合了 DNS 传输层（`sendHttpDNS`/`sendStreamDNS`、`idBitmap` 流水线 ID 分配、`responseSlot` 池）与控制器逻辑；component/dns 负责路由程序编译（routing_program/function_parser）与 upstream 类型抽象。边界尚清晰，但 control/dns.go 内“传输机制”与“控制平面”两类职责耦合在同一文件（D1）。 | 可将传输相关（HTTP3/stream DNS、idBitmap）抽到独立传输子包，降低 control/dns.go 体量（1445 行）。非必须。 |
| P3 | [control/dns_control_optimistic.go:36](control/dns_control_optimistic.go#L36) | **optimistic 刷新标志清理可能误清新缓存条目的标志**。`backgroundRefresh` 的 defer 通过 `c.LookupDnsRespCache(cacheKey)` 取**当前**缓存并 `MarkRefreshed()`。若期间该 key 被驱逐并由新请求重建为新的 `*DnsCache`，且新条目恰好也被另一 goroutine 置为 refreshing，此 defer 会过早清掉新条目的 refreshing，触发一次重复回源（D2）。后果仅为多余上游查询，无正确性问题。 | 可在 `backgroundRefresh` 入口捕获触发刷新时的具体 `*DnsCache` 指针，defer 中仅当当前缓存仍是同一指针时才清标志。 |
| P3 | [control/control_plane_core.go:954](control/control_plane_core.go#L954) | **conn state tracker BPF 删除失败时元组孤儿**。`ReleaseUdpConnStateTuples` 用 `defer FinalizeRelease` 保证 tracker 条目总是清理（无死锁，设计正确），但当 `BpfMapBatchDelete` 返回错误时，tracker 条目已移除而 BPF ConnStateMap 中元组可能残留，造成短暂孤儿（D6）。 | 非阻塞问题；可在删除失败时记录 metric 以便观测孤儿积累。 |
| P3 | [control/udp_unordered_task_runner.go:43](control/udp_unordered_task_runner.go#L43) | **unordered task runner 无 Close/Wait，无优雅排空**。worker 仅靠 `ctx.Done()` 退出，ctx 取消时队列内待办任务被静默丢弃，且无 WaitGroup 供调用方确认 worker 已退出（D6）。对 UDP 尚可接受，但生命周期可观测性弱。 | 增加 `Close()` 显式取消 ctx + `Wait()` 等待 worker 退出，便于 reload 时确定清理完成。 |
| P3 | [control/dns_control.go:1290](control/dns_control.go#L1290) | **LRU 驱逐每轮两次全量 Range**。`evictLRUIfFull` 先 `Range` 计数再 `Range` 收集条目（含 heap 选择），O(n)×2。虽在后台 janitor goroutine 不阻塞热路径，但大缓存（>5000）时每轮开销可见（D6/性能）。 | 可在单次 Range 内同时计数与收集，或维护近似计数器避免每次重扫。 |
| P3 | [control/tcp_copy_linux.go](control/tcp_copy_linux.go)、[control/tcp_copy_other.go](control/tcp_copy_other.go) | **splice pipe 池与缓冲池设计良好（正面记录）**。`relaySplicePipePool` 有上限 64，`putRelaySplicePipe` 在 `pipe.data != 0`（数据残留）时直接 close 而非复用，避免污染；`relayCopyBufferPool` 正确 defer 归还。无泄漏。 | 无需改动，记录为已核验良好实践。 |
| P3 | [control/raw_udp_other.go:1](control/raw_udp_other.go#L1) | **raw_udp build tag 对称性良好（正面记录）**。`sendUDPv4RawInDaeNetns`/`sendUDPv6RawInDaeNetns` 在 linux 与 other 两侧对称；linux 额外的 `*RawDirect` + checksum 仅供 linux 测试与内部使用，不影响对称性。 | 无需改动。 |

## 检查点逐项核验

### T2 — DNS 子系统

| 检查点 | 结论 |
|---|---|
| DNS 缓存 COW 与 LRU 一致性（D2） | **已检查，设计良好**。`packedResponse` 用 `atomic.Pointer` 实现 lock-free COW；`lastAccessNano`/`deadlineNano` 均为 atomic；`CloneForReload` 明确共享不可变 Answer/NS/Extra 切片并以 WARNING 文档化不变量（[dns_cache.go](control/dns_cache.go)）。读取路径无锁，刷新走 CAS。 |
| singleflight 失败缓存（D2） | **发现问题（P2）**。失败/NXDOMAIN 不缓存，见上表 [dns_control.go:2259](control/dns_control.go#L2259) 与 [dns_control.go:1530](control/dns_control.go#L1530)。 |
| conn pool 释放（D6） | **已检查，未发现问题**。`dnsForwarderCache` 有 janitor（`evictIdleDnsForwarders`）+ `closeAllDnsForwarders` 在 `Close` 中清理；bpf update worker 用有界 channel + `bpfUpdateClosed` atomic 防止关闭后发送。 |
| optimistic 更新竞态（D2） | **发现轻微问题（P3）**。refreshing 标志清理跨缓存实例的竞态，见上表 [dns_control_optimistic.go:36](control/dns_control_optimistic.go#L36)。CAS 保证仅一个 goroutine 触发刷新，正确性无碍。 |
| 负缓存 TTL（D6） | **发现问题（P2）**。NXDOMAIN/SERVFAIL 不入缓存，见上表。NODATA 有 `minFirefoxCacheTtl` 兜底。 |
| 与 component/dns 职责重叠（D1） | **已检查，边界清晰（P3 命名建议）**。见上表。 |

### T3 — TCP relay

| 检查点 | 结论 |
|---|---|
| copy goroutine 退出路径（D2/D6） | **已检查，未发现问题**。`relayCore.run`（[tcp_relay_core.go](control/tcp_relay_core.go)）用共享 ctx + `forceCloseOnce` + `SetReadDeadline(past)` 双向解阻塞；任一方向出错即 cancel+forceClose，`watchDone` defer 防止 ctx 泄漏。半关闭超时 10s 有界。 |
| 零拷贝/gather 路径正确性（D5） | **已检查，未发现问题**。`shouldUseRelayFastPath` 要求两端均可 unwrap 为 `*net.TCPConn`；`tryRelayGatherWrite` 先消费 prefix/segments 再进入主循环；`unwrapRelayTCPConn` 迭代深度有上限 8。 |
| sniff policy 与 copy 协调（D2） | **已检查，未发现问题**。`prefetchForTcpSniff` 用 `prefixedConn` 回放已读字节，失败入负缓存（`tcpSniffNegSet`，3 次失败抑制 10 分钟）；负缓存有 RWMutex 保护且有 janitor `cleanupTcpSniffNegative`。 |
| linux/other 文件对称性（D5） | **发现死代码（P2）**。`tryOffloadTCPRelay` 仅 other 定义且无调用方；`relayFastCopy`/`shouldUseRelayFastPath`、`tryRelayGatherWrite` 两侧对称完整。见上表。 |

### T4 — UDP relay

| 检查点 | 结论 |
|---|---|
| UDP 无序处理正确性（D2） | **已检查，未发现问题**。`udpUnorderedTaskRunner`（[udp_unordered_task_runner.go](control/udp_unordered_task_runner.go)）按 hash 分桶保同 key 顺序，overflow bucket 兜底；worker 由 ctx 退出。`UdpTaskPool.convoy` 保 per-flow FIFO，DNS/SIP/RTP/STUN 走直发 goroutine 绕过队列（[udp_flow.go](control/udp_flow.go) `ShouldUseGoroutineDirectly`）。 |
| endpoint pool janitor 竞态（D2） | **已检查，未发现问题**。`UdpEndpointPool` 64 分片，janitor 在锁外执行 `Close`（[udp_endpoint_pool.go:1773](control/udp_endpoint_pool.go#L1757)）；`GetOrCreate` 用 `createMu` 串行化同 key 创建；`retire`→`selfRemoveFromPool` 用 CAS 删除自检。`watchTransportLifecycle` 在 transport 结束后回收 endpoint。 |
| conn state tracker 竞态（D2） | **已检查，未发现问题**。`udpConnStateTracker` 用 cond-var 等待 `deleting` 完成；`ReleaseUdpConnStateTuples` 以 `defer FinalizeRelease` 保证配对，无死锁。轻微孤儿问题见 P3。 |
| task pool 满载处理（D6） | **发现问题（P2×2）**。overflow 无上限增长 + convoy panic 误删，见上表。`udpEndpointReplyQueueSize=256` 满时对 read loop 施加背压（有意设计，[udp_endpoint_pool.go:680](control/udp_endpoint_pool.go#L680)），此处正确。 |

---

## 备注

- 本次为只读审阅，未运行测试，未修改源码。
- 行号基于审阅时的工作区状态，后续提交可能漂移。
- 发现汇总将回填至 [docs/sprint-1/progress.md](docs/sprint-1/progress.md) 的 T2/T3/T4 行。
