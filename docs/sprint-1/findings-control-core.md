# Sprint 1 发现清单 — T1 / T5 / T6（control/ 编排核心、BPF 生命周期、拨号与路由）

> 只读审阅，未修改任何源码。审阅对象见 `plan.md` 的 T1/T5/T6 章节。
> 行号基于审阅时的工作区状态，可能随后续提交漂移。

严重度图例：P0 致命 / P1 严重 / P2 一般 / P3 建议。

---

## T1 — control/ 编排核心（D1 职责划分 / D2 并发安全 / D6 资源生命周期）

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P1 | control/control_plane.go:46-118 | **ControlPlane 上帝对象**：struct 嵌入 `controlPlaneCore`/`controlPlaneGenerationState`/`controlPlaneDNSRuntime`/`controlPlaneDatapathJanitor` 四个子结构后，自身仍直接持有 realDomain bloom 过滤器、realDomainNegSet、dnsDialerSnapshot/penalty、tcpSniffNegSet、failedQuicDcidCache、udpUnorderedRunner、listenerFiles、pendingDnsReloadCache 等十余类异质状态。control_plane.go 单文件 3804 行，跨 DNS 路由、负缓存、拨号器快照、监听 socket 发布、datapath janitor 等多个领域。测试与 reload 路径需理解全部耦合，维护成本高。 | 将 realDomain 探测（bloom+negSet+singleflight）、dnsDialer 缓存（snapshot+penalty）、tcpSniff 负缓存各自拆分为独立组件（类似 `controlPlaneDatapathJanitor` 的嵌入模式），使 ControlPlane 仅保留生命周期编排。 |
| P2 | control/control_plane_core.go:358-365 (`Close`) | **Close 嵌套 goroutine 泄漏风险**：`closeTail`（control_plane.go:3603）在 `isBpfEjected()` 路径下 spawn `go func(){ done <- core.Close() }()`，外层用 `time.After(controlPlaneDeferredCleanupTimeout)` 兜底。若 `netlink.FilterDel` 在虚拟/PPPoE 接口上永久阻塞，内层 goroutine 永不退出（`done` channel buffered(1) 仅防发送阻塞，不防 Close 卡死）。注释已承认此限制，但仍构成确定性 goroutine+FD 泄漏。 | 为 netlink 调用包裹 per-call context/超时（netlink 库目前不支持 context，可用 `context.AfterFunc` + 后台异步 FilterDel 的方式记录未完成项）；或在卡死时记录 filter handle 供下次启动 `PurgeStaleTCFilters` 兜底清理。 |
| P3 | control/control_plane_core.go:309-317 (`addManagedBpfHookCleanup`) | **双重 detach 竞态**：`addDeferFunc`（持 `deferMu`）与 `addBpfHookDetach`（持 `bpfHookMu`）是两个独立临界区。若 `Close()` 在两者之间执行，detachFunc 会被 `Close` 的 deferFuncs 执行一次，随后 `addBpfHookDetach` 注册它，`DetachBpfHooks()` 再执行一次。detach 函数容忍 `ENOENT`/`ENODEV`/`os.IsNotExist`，故无崩溃，仅产生冗余 netlink 调用与日志噪音。 | 将两段注册合并到单一临界区（或在 `addDeferFunc` 成功后用同一把锁追加到 `bpfHookDetachFuncs`），或为 detachFunc 增加幂等标记（`sync.Once`）。 |
| P3 | control/control_plane_core.go:467-471 / 478-482 (`BatchUpdateDomainRouting`/`BatchRemoveDomainRouting`) | **`domainRouting` nil-check-then-assign 无锁**：`if c.domainRouting == nil { c.domainRouting = newDomainRoutingTracker() }` 在无锁路径执行。`newControlPlaneCore` 构造时已赋值，该分支实际永不触发（死代码），但模式本身是数据竞争隐患——若未来重构令该字段可空，将引入竞态。 | 删除防御性 nil 分支（构造保证非 nil），或将字段改为构造后只读。 |
| P3 | control/sysctl.go:55-77 (`SysctlManager.startWatch`/`InitSysctlManager`) | **watcher goroutine 无 Close**：`startWatch` 仅在 `watcher.Events`/`Errors` channel 关闭时退出，但 `SysctlManager` 从不调用 `watcher.Close()`。`InitSysctlManager` 为 `sync.Once` 单例，跨 reload 不重复创建，故无 per-reload 泄漏；但进程级 goroutine + fsnotify FD 永不释放，`expectations` map 跨 reload 单调增长（每次 `Set(..., watch=true)` 追加路径）。 | 为 `SysctlManager` 增加 `Close()` 并在进程退出路径调用；reload 时清理上一代不再需要的 expectation 条目。 |

### T1 检查点覆盖说明
- **ControlPlane 是否上帝对象**：是（见 P1）。
- **stop/done/ready channel 生命周期**：已检查，未发现问题。`ready`/`negJanitorStop`/`connStateJanitorStop` 均为单发送者 `close()`，配合 `sync.Once`/`CompareAndSwap` 防重复关闭；`stopRealDomainNegJanitor`/`stopConnStateJanitor` 用 `gracefulShutdownWaitTimeout` 等待退出。
- **drain 路径完整释放**：已检查，未发现确定性泄漏。`controlPlaneDrainTracker.Acquire` 返回 `sync.Once` 释放函数，`Serve` 中 TCP 连接先 acquire ticket 再 register，连接关闭时 release；`AbortConnections` 关闭 `inConnections` 中所有连接。`drainTracker.IdleCh()` 在 active 归零时 close。
- **reload 新旧 plane 竞态**：已检查，关键顺序契约由 `MarkRetired()`（control_plane.go:3555）+ `retired atomic.Bool`（connectivity.go:31）保障——旧代标记 retired 后 `outboundAliveChangeCallback` 跳过 BPF map 写入，避免覆盖新代 liveness。`EjectBpf`/`InjectBpf`/`EjectLpmIndices`/`InheritLpmIndices` 实现 BPF 对象与 LPM slot 的所有权移交。

---

## T5 — control/ BPF 管理与生命周期（D2 map 更新竞态 / D3 map 生命周期与 FD / D6 泄漏）

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P3 | control/bpf_utils.go:511-525 (`fullLoadBpfObjects` retry) | **goto retry 无显式计数**：`ErrMapIncompatible` 时移除 pinned map 后 `goto retryLoadBpf`。每次迭代移除一个 map，理论上被 map 种类数上限约束，但缺少重试计数器，可读性差；若出现与 "use pinned map" 前缀匹配但移除无法解决的持续错误，会反复重试。 | 增加最多重试 N 次（= map 种类数）的显式计数与日志。 |
| P3 | control/routing_matcher_builder.go:537-562 (`globalNextLpmIndex` 环形分配) | **大 count 时 ring 无法防重叠**：`getNextRingLpmIndex` 做 `(start+count)%MaxMatchSetLen`。当 `lpmCount` 接近 `MaxMatchSetLen` 时，新分配区间会覆盖上一代尚未清理的 slot。实际 `lpmCount << MaxMatchSetLen`，且 `InheritLpmIndices`/`ReplaceLpmIndices`（control_plane_core.go:434-498）兜底清理继承 slot，影响有限。 | 在 `reserveLpmRingSlots` 中校验 `count <= MaxMatchSetLen/2` 或记录告警；文档化环形仅对小 count 有效的前提。 |
| P3 | control/netns_utils.go:148-167 (`DaeNetns.With`) | **netns 切换下 goroutine 转移陷阱**：`With` 用 `runtime.LockOSThread`+`netns.Set`，defer 顺序（先 netns.Set 回 host，后 UnlockOSThread）正确。但若 `f()` 内部 `go ...` 启动新 goroutine，该 goroutine 不继承 OS 线程绑定，可能运行在任意 netns 的线程上——经典 netns footgun。当前调用点（FilterAdd/createAnyfromSocket）不内部 spawn goroutine，故未触发。 | 在 `With` 文档注释中显式警告"禁止在 f 内部启动依赖 daens 的 goroutine"。 |

### T5 检查点覆盖说明
- **map 加载/卸载时序**：已检查，未发现问题。`controlPlaneCore.Close` 先清 LPM slot、cancel context、再逆序执行 deferFuncs（含 TC filter detach），最后条件性 `bpf.Close()`（仅 `bpfOwned`）。`addManagedBpfHookCleanup` 同时注册到 deferFuncs 与 bpfHookDetachFuncs，保证 SIGTERM 快速 detach 与正常 Close 都覆盖。
- **reload purge 完整性**：已检查，未发现问题。`clearReloadDomainRoutingMap`（control_plane.go:855）仅清 `domain_routing_map`，conn-state map 经 Scheme3 对象移交保留（注释明确禁止清除，否则已建立流丢失缓存被重路由）。`cleanupPinnedConnStateMapFiles`（bpf_utils.go:386）仅在全新加载（`_bpf==nil`）时清理 stale pin。
- **batch delete 边界**：已检查，未发现问题。`BpfMapBatchDeleteAll`（bpf_utils.go:298）分块（chunk=1024）删除，容忍并发 key 消失（忽略 `ErrKeyNotExist`），不支持 batch 时降级为 `BpfMapDeleteAll` 迭代器扫描。`isBatchLookupUnsupportedErr` 检测内核不支持并降级。
- **netlink 错误处理**：已检查，未发现问题。`delQdisc`/`FilterDel` 容忍 `ENOENT`/`ENODEV`/`os.IsNotExist`；`bindDaens` 用 `WithBestEffort`/`WithRequired` 区分关键与非关键操作。
- **netns 切换隔离**：已检查，未发现问题。`Setup` 用 `setupDone atomic.Bool`+`mu` 双检查保证幂等；`With` 正确 LockOSThread 并恢复 host netns。
- **buildRoutingKernspace 并行正确性**：已检查，未发现问题。并行 `newLpmMap` 操作各自本地 map；共享 `LpmArrayMap.Update` 在 `mu` 下序列化；`firstErr` 在 `mu` 下合并；`results[idx]` 各 goroutine 写不同下标，预分配无扩容。

---

## T6 — control/ 拨号与路由匹配（D1 边界 / D2 池并发 / D6 拨号失败处理）

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P2 | control/domain_routing_tracker.go:160-205 (`syncOwner`) | **持锁执行 BPF batch 操作**：`t.mu` 在整个 `syncOwner` 期间持有，包括 `BpfMapBatchUpdate`/`BpfMapBatchDelete`。在 `SimulateBatchUpdate=true`（旧内核）时退化为逐条循环，每次 DNS A/AAAA 解析回调都会串行化所有 domain_routing 更新。高并发 DNS 场景下成为热点。内存状态与 BPF map 需一致故难完全拆分。 | 先在锁内计算 keysToUpdate/keysToDelete 的 diff 快照并复制出所需数据，释放锁后再做 BPF batch；或为 BPF 操作引入 per-key 细粒度锁（按 IP hash 分片）。需权衡一致性窗口。 |
| P3 | control/anyfrom_pool.go:355-401 (`GetOrCreate` createMu) | **createMu 跨 netns.ListenPacket 持有**：`createAnyfromSocket`（含 `LockOSThread`+`netns.Set`+`ListenPacket`）在 per-shard `createMu` 内执行，同 shard 不同地址的创建被串行化。64 shard 缓解，但大量地址哈希到同 shard 时吞吐受限。 | 将 socket 创建移出 `createMu`（先创建再在 createMu 下 double-check 插入），仅保留插入段的串行化。注意失败负缓存路径也需调整。 |
| P3 | control/routing_matcher_userspace.go:127-135 (`Match` 域位图) | **域位图按 match 下标 i 寻址**：`(domainMatchBitmap[i/32]>>(i%32))&1` 假设 match 在 `compiledMatches` 中的线性下标对应 domainMatcher 注册的位。`i/32 < len(domainMatchBitmap)` 做了越界保护，逻辑正确，但隐式契约（builder 与 matcher 的下标必须同序）未在类型层面强制，重构时易破。 | 在 builder/matcher 间显式记录"domain match 下标 == compiledMatches 下标"的不变量注释或断言。 |

### T6 检查点覆盖说明
- **dial family fallback 正确性**：已检查，未发现问题。`chooseProxyDialer`（dial.go:103）UDP 路径按 client IP 版本对齐 selectionNetworkType；`SelectWithExclusionResult` 失败时 `alternateNetworkType` 切换 v4/v6 重试（`strictIpVersion=false` 放宽）；`endpointNetworkTypeForSelection` 根据准入类型回填端点版本。`routeDial`（dial.go:238）最多 2 次尝试，`shouldForceMarkUnavailableOnProxyDialError` 触发强制标记不可用后重选。
- **routing matcher 构建幂等**：已检查，未发现问题。`NewRoutingMatcherBuilder` 纯构建，`compiledMatches`/`lpmMatcher`/`domainMatcher` 构建后只读；`Match`（routing_matcher_userspace.go:83）无写共享状态，`domainMatchBitmap` 每次 match 新分配。`BuildKernspace`/`KernspaceSnapshot().BuildKernspace` 分离快照与提交，支持 prepared/commit 两阶段。
- **domain tracker 并发更新**：见 P2（syncOwner）。`applyOwnerSnapshotLocked` 先清除旧 owner 影响的 IP、再写入新 owner，`desiredBitmapForKeyLocked` 计算多 owner OR 合并，逻辑正确。
- **anyfrom 池竞态**：已检查，未发现问题。`GetOrCreate` RLock 快路径 + `createMu` 防惊群 + double-check；负缓存（`failed atomic.Bool`+`expiresAtNano`）过期后 fall-through 重建；`Anyfrom.Close` 守卫 nil UDPConn；janitor 两阶段（锁内收集、锁外关闭）最小化持锁。`pins atomic.Int32` 支持长生命周期 owner 保活。
- **latency 探测超时**：已检查，未发现问题。`node_latency.go` 为只读快照路径，不发起探测；`TriggerLatencyChecks` 仅 `NotifyCheck`，实际超时由 dialer 包（`consts.DefaultDialTimeout`）控制，`routeDial` 每次 attempt 独立 `context.WithTimeout`+`cancel`。
- **拨号失败处理**：已检查，未发现问题。`notifyProxyDialerHealthCheck`（dial.go:51）区分 TCP/UDP 通知；`ReportUnavailableForced`/`NotifyCheckDnsUdp`/`NotifyCheckTcp` 按错误类型路由；可忽略错误（`IsCanceledOrClosed`/`IsIgnorableConnectionError`）跳过惩罚。

---

## 汇总

| 严重度 | 数量 |
|---|---|
| P0 致命 | 0 |
| P1 严重 | 1（ControlPlane 上帝对象） |
| P2 一般 | 2（Close 嵌套 goroutine 泄漏、syncOwner 持锁做 BPF 操作） |
| P3 建议 | 7 |

**最突出的架构问题**：
1. **ControlPlane 上帝对象**（P1）：单 struct/单文件聚合 DNS 路由、负缓存、拨号器快照、监听 socket、datapath janitor 等，测试与 reload 路径耦合度高。已有 `controlPlaneDatapathJanitor`/`controlPlaneDNSRuntime` 嵌入拆分的先例，可继续推广。
2. **reload 生命周期的正确性高度依赖调用顺序契约**（跨 T1/T5/T6）：`MarkRetired`→健康检查启动、`EjectBpf`→`InjectBpf`、LPM slot 移交等均要求 cmd/ 层严格排序。control/ 内部用 `retired`/`bpfEjected`/`closeOnce` 等标志防重入，但缺少跨层顺序的断言或状态机封装，错误顺序可能导致共享 BPF map 被旧代 clobber（当前由注释 + 调用方纪律保障）。
