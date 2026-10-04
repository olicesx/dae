# 不可达 / 遗留冗余设计清理清单

- 来源：对 HEAD `ee4ce271` 的全仓检索（`golangci-lint`、`go vet`、`deadcode`、`unparam`、导出符号零引用扫描、eBPF 程序/map 交叉核对、两路独立审计 + 逐条复核）
- 用途：按批次执行删除或收窄；每个批次都有独立验证门
- 约定：
  - **动作**：`DELETE` = 删；`NARROW` = 收窄签名/删死分支；`DECIDE` = 需维护者先裁决；`KEEP` = 明确不要删
  - **风险**：`低` = 零引用，删了只影响编译；`中` = 涉及签名/调用点；`高` = 涉及行为语义
  - 行号为 HEAD `ee4ce271` 时点，执行时以符号为准
- **状态（2026-10-05 复核，HEAD `b1771731`）**：批次 1/2/3/5 与 4.1/4.2/4.3 已全部落地（提交见文末「执行记录」）；批次 4.4 与 6.11–6.14 属导出面，仓内无法证伪仓外消费者，**保留并登记**；执行记录的哈希已按实际提交更正。复核发现与处置见文末「自检复核」。

## 验证门（每批执行后）

```bash
gofmt -l . && go build -tags dae_stub_ebpf ./...
go test -tags dae_stub_ebpf ./...
go test -race -tags dae_stub_ebpf -timeout 30m ./control/... ./component/... ./cmd/...
golangci-lint run --build-tags dae_stub_ebpf ./...
# 仅第 4/5 批涉及内核侧时：
make ebpf-sync-check && make ebpf-lint
```

---

## 批次 1 — 纯删除：全仓零引用（含测试），无接口义务

> 建议一个 commit 一项或一组同源项（如 `ebpf.go` 常量、`quic.go` 常量各一组）。

| # | 位置 | 符号 | 判定依据 | 动作 | 风险 |
|---|---|---|---|---|---|
| 1.1 | `common/consts/ebpf.go:27-32` | `BigEndianTproxyPortKey`、`DisableL4TxChecksumKey`、`DisableL4RxChecksumKey`、`ControlPlanePidKey`、`ControlPlaneNatDirectKey`、`ControlPlaneDnsRoutingKey` | 旧 `param_map` 数组 ABI 遗留；C 侧已改 `const volatile struct dae_param PARAM`（`tproxy.c:227`），无 `param_map`。这批是 `iota` 中段，且 `ZeroKey`/`OneKey`/`TwoKey` 均为显式赋值，删除不改变取值 | DELETE | 低 |
| 1.2 | `common/consts/ebpf.go:38,41-43` | `type DisableL4ChecksumPolicy` + `_EnableL4Checksum`/`_Restore`/`_SetZero` | 全仓（含 C/docs）无任何 `l4_checksum` 符号，功能已不存在 | DELETE | 低 |
| 1.3 | `common/consts/ebpf.go:177,178` | `TproxyMarkString`、`Recognize` | 零引用；`TproxyMark`（:176）在用，勿动。**注意**：删掉这两行后该 `const` 组只剩 `TproxyMark` 一个有显式类型，触发 `SA9004`（staticcheck）→ 必须同时给 `LoopbackIfIndex` 补显式类型（`int`）或拆组，否则 lint 失败。`LoopbackIfIndex` 是**无类型常量**（`= 1` 自带表达式，不继承上一行类型），所以补类型不改变语义。已实测 | DELETE | 低 |
| 1.4 | `component/outbound/filter.go:46` | `FilterInput_Link` | 零引用 | DELETE | 低 |
| 1.5 | `component/outbound/dialer/dialer.go:69,70` | `ErrUnexpectedField`、`ErrInvalidParameter` | 零引用 | DELETE | 低 |
| 1.6 | `component/sniffing/quic.go:17,18,29` | `QuicFlag_PacketNumberLength`、`QuicFlag_Reserved`、`QuicVersion1` | 零引用（`QuicFlag_FixedBit` 见 2.10，测试用） | DELETE | 低 |
| 1.7 | `component/outbound/dialer_group.go:333` | `(*DialerGroup).SelectWithExclusion` | 已被 `SelectWithExclusionResult`（多返回 `selectedNetworkType`）完全取代；`Select`（:324）已直连新函数 | DELETE | 低 |
| 1.8 | `component/outbound/dialer/connectivity_check.go:1351` | `(*Dialer).Check` | 注释自称 "Backward compatibility wrapper"；生产统一走 `d.check(opts,false,nil)` | DELETE | 低 |
| 1.9 | `component/daedns/router.go:377,388` | `(*Router).MatchSubscriptionUpstream`、`MatchNodeUpstream` | 逻辑已内联进 `WrapSubscriptionDialer`/`WrapNodeDialer`；零调用 | DELETE | 低 |
| 1.10 | `control/control_plane_core.go:319` | `(*controlPlaneCore).Flip` | 零引用；flip 由 `prepareBpfHookFlip`/`commitBpfHookFlip`/`activateBpfHookFlip` 驱动 | DELETE | 低 |
| 1.11 | `control/dns_controller_cache.go:981` | `LookupDnsRespCache` | 零调用，生产全走 `LookupDnsRespCache_` | DELETE | 低 |
| 1.12 | `control/dns_cache.go:578` | `(*DnsCache).IncludeIp` | 唯一调用点（异步淘汰器 `next.IncludeIp(ip)`）已由 `caa4074e` 删除；共享 IP 保护改由 domain-routing tracker 的 per-owner 引用计数承担。注意 `dnsAnswerIP`（`:587`）仍被 `control_plane_core_routing.go:58` 使用，**保留** | DELETE | 低 |
| 1.13 | `common/consts/ebpf.go:100` | `FtraceFeatureVersion` | 自带 `Deprecated` 注释；trace 已改 fentry/kprobe | DELETE | 低 |
| 1.14 | `common/consts/ebpf.go:102,105,106,111` | `CgSocketCookieFeatureVersion`、`ProgTypeSkLookupFeatureVersion`、`SockmapFeatureVersion`、`TcxFeatureVersion` | 零引用；对应能力门控已换成 CVE 门控（`TcpSockmapPanicSafeVersion`/`RedirectPeerSafeVersion` + `DAE_ALLOW_TCP_SOCKMAP`）。**删前把「该能力需要的内核版本」写进对应门控处注释**，否则丢知识 | DELETE | 低 |

---

## 批次 2 — 仅测试引用：生产不可达

> 逐项判定是「测试专用 API（保留）」还是「被取代的旧包装（删除）」。

| # | 位置 | 符号 | 测试引用 | 动作 | 风险 |
|---|---|---|---|---|---|
| 2.1 | `component/outbound/filter.go:85` | `(*DialerSet).ParseFailureCount` | `filter_log_test.go` | DELETE（`parseFailures` 字段随之可删，除非保留观测面） | 低 |
| 2.2 | `control/packet_sniffer_pool.go:1041` | `(*PacketSnifferPool).releaseFlowFamily` | `packet_sniffer_pool_test.go`、`udp_sniffer_loss_test.go` | DELETE（测试改调 `releaseFlowFamilyRef`） | 低 |
| 2.3 | `control/packet_sniffer_pool.go:994` | `deleteFlowFamilyMember` | `udp_sniffer_loss_test.go` | DELETE | 低 |
| 2.4 | `control/dns_cache.go:192` | `(*DnsCache).FillInto` | `dns_cache_fuzz_test.go` | DELETE（测试改调 `FillIntoWithTTL`）；被 `FillIntoWithTTL` 取代 | 低 |
| 2.5 | `common/consts/dialer.go:54` | `(L4ProtoStr).ToL4Proto` | `dialer_test.go` | DELETE；已由 `ToL4ProtoType`（映射 eBPF 枚举）取代 | 低 |
| 2.6 | `component/sniffing/quic.go:20` | `QuicFlag_FixedBit` | `quic_test.go` | **KEEP**（测试位掩码语义依赖） | — |
| 2.7 | `control/anyfrom_pool.go:354` | `(*AnyfromPool).Close` | `pool_janitor_test.go`、`cmd/run_shutdown_test.go` | **KEEP**（生产进程级 pool 不关闭，测试需要它做 goleak 清理；非"过时设计"） | — |
| 2.8 | `control/bpf_host_abi.go:43` | `bpfHostABI.putUint64` | `event_ringbuf_test.go` | **KEEP**（与 put16/put32 及读侧对称的编解码 API） | — |
| 2.9 | `control/control_plane_core_bind_event.go:160,168` | `bindAttemptCount`、`bindFailureCount` | 测试 | **KEEP**（计数器生产在写，测试读取；保留观测能力） | — |
| 2.10 | `control/tc_hook_handoff.go:23` | `ownedTCHookSet` | `tc_hook_set_test.go` | **KEEP**（断言原语） | — |
| 2.11 | `control/udp_task_pool.go:61,125` | `udpTaskFunc.Run`、`udpTaskQueueTrace.snapshot` | order/diag 测试 | **KEEP**（注释已声明是 test/bench + 诊断支撑） | — |
| 2.12 | `control/udp_task_pool.go:501` | `(*UdpTaskPool).DroppedTasks` | `udp_task_pool_order_test.go` | **KEEP**（过载观测面） | — |
| 2.13 | `control/dns_cache.go:192` 之外的 `Hijack/TsigStatus/TsigTimersOnly`（`control/tcp.go:560-566`） | — | — | **KEEP（硬约束）**：`dnsmessage.ResponseWriter` 的必需实现，删了破坏接口 | — |

---

## 批次 3 — 收窄签名：死参数 / 死返回值 / 死分支（生产可达代码内）

> 每项都可独立提交。核心是删掉「恒常量」的入参、恒 nil 的返回、恒不可达的分支。**不要顺手改语义**。

| # | 位置 | 问题 | 证据 | 动作 | 风险 |
|---|---|---|---|---|---|
| 3.1 | `control/udp.go:579,615`（用点 `:818`） | `skipSniffing` 恒 `false` → `!skipSniffing` 恒真 | 唯一入口 `udp_ingress_task.go:346` 传字面量 `false` | NARROW | 中 |
| 3.2 | `control/udp.go:615` | `handlePktOwned` 的 `lConn` 完全未使用（贯穿 3 层只传不用） | 函数体内 0 次出现 | NARROW（连同 `handlePktWithPrefetch`、ingress 调用点） | 中 |
| 3.3 | `control/udp.go:501`（调用点 `:580-582`） | `handleRetainedUDPEndpoint` 第二返回值恒 `nil` → 错误分支死 | 所有 return 均返回 nil | NARROW | 中 |
| 3.4 | `control/udp.go:213`（用点 `:214`） | `ChooseNatTimeout` 的 `sniffDns` 恒 `true`，false 分支死 | 唯一调用者 `udp_ingress_task.go:195` 传 `true` | NARROW | 中 |
| 3.5 | `control/udp_endpoint_lifecycle.go:874,876` | `setExpiry` 的 `refreshCachedResponseConns` 恒 `true` | 两个调用点均传 `true` | NARROW | 中 |
| 3.6 | `control/control_plane_core.go:552` | `buildRoutingKernspaceForSlot` 的 `[]uint32` 返回值无人使用 | 3 个调用点全部 `_, err =`；副作用 `c.lpmTrieIndices = ...` 才是目的 | NARROW | 中 |
| 3.7 | `control/tc_hook_handoff.go:151` | `beginTCHookReplace` 的 `bool` 返回值无人使用 | `control_plane_datapath.go:119` + 测试均 `_` | NARROW | 中 |
| 3.8 | `control/tcp_offload_linux.go:376`（调用点 `:572-576`） | `fuseStep` 的 `err` 恒 `nil` → 调用点 `forceClose` 恢复分支死 | 所有 return 均为 nil | NARROW（删 err 或保留但删死分支，二选一并注释理由） | 中 |
| 3.9 | `control/tcp_relay_core.go:92` | `newRelayCore` 的 `engine` 恒为 `defaultRelayCopyEngine{}` | 生产与全部测试同值 | DECIDE→NARROW：若确认不再需要替换引擎，删参数；否则注释保留注入缝 | 中 |
| 3.10 | `control/anyfrom_pool.go:371` | `getOrCreateWithMark` 的 `ttl` 恒 `AnyfromTimeout` | 3 个调用点全传常量 | NARROW | 中 |
| 3.11 | `control/dial.go:106` | `chooseProxyDialer` 的 `ctx` 未使用 | — | NARROW | 中 |
| 3.12 | `control/dns_runtime.go:231` | `startPreparedDNSListenerWithWarmupTimeout` 的 `log` 未使用 | 函数体内 0 次出现 | NARROW | 中 |
| 3.13 | `cmd/runtime_supervisor.go:193` | `markRetirementComplete` 的 `bool` 返回值生产无人使用 | `reload_manager.go:368,470` 丢弃 | NARROW | 中 |
| 3.14 | `component/sniffing/conn_sniffer.go:203,209` | `copyDirect` 的 `record` 回调恒 `nil` → 记账块死 | 两个调用点 `:68`、`:196` 都传 `nil` | NARROW | 中 |
| 3.15 | `component/outbound/dialer/recovery_state.go:109` | `indexForProto` 的 UDP 分支不可达 | `protoIdx` 两个调用者均传 `L4ProtoStr_TCP`（`dialer.go:387`、`connectivity_check.go:900`） | NARROW | 中 |
| 3.16 | `component/outbound/dialer/dialer.go:213`（写点 `:277`） | `GlobalOption.CheckDnsTcp` 只写不读 | 全仓无读取点 | NARROW（删字段与写入） | 中 |
| 3.17 | `component/outbound/dialer_group.go:300` | `logNoAlive` 的 `strictIpVersion` 未使用 | — | NARROW | 中 |
| 3.18 | `config/config.go:202-204` | `if !ok { if spec.required { return ... } }` 不可达（上一个循环已保证 required 段存在，且 map 期间不变） | 代码注释自认 "Unreachable" | NARROW（或 KEEP 作为防御性守卫，二选一） | 低 |
| 3.19 | `control/dns_controller_cache.go:1038-1040`（调用点 `364,420,468`） | `ignoreFixedTtl` 恒 `false` → `else { deadline = cache.OriginalDeadline }` 臂死 | 3 个生产调用点全传 `false` | NARROW | 中 |
| 3.20 | `control/udp_flow.go:232` | `ShouldAttemptSniff` 零引用 | `85a1fc3c` 加入即无调用——**从未接线**，非"过时" | DECIDE→DELETE | 低 |
| 3.21 | `control/tcp.go:386` | `RouteDialTcpContext` 零引用 | `85a1fc3c` 加入即无调用 | DECIDE（见批次 6 API 面讨论） | 中 |

---

## 批次 4 — 结构性残留：机制已被取代，只剩空壳

| # | 位置 | 说明 | 证据 | 动作 | 风险 |
|---|---|---|---|---|---|
| 4.1 | `control/control_plane_dns.go:220,228-229,234-246,251-260` + `control/control_plane.go:72,3105` | `owned` 状态机残留：`dnsHandoffOwned` 恒 `false`，`releaseRetainedState` 的 `if owned && handoff != nil { handoff.Close() }` 恒不进入 | `e6023169` 已删掉唯一产生 `owned=true` 的 `DetachDnsController`/`EnableDNSHandoff`，但 `owned` 参数/字段/返回值没跟着删；唯一 setter `:269` 传字面量 `false` | DELETE（连同 `owned` 参数与返回值，收敛为无 owned 语义） | 中 |
| 4.2 | `control/udp_endpoint_pool.go:46` + `control/conn_state_pinning.go:67` + `control/control_plane_core_routing.go:122` | 接口方法 `TransferRetainedUdpConnStateTuplesFrom` 两个实现均无调用 | 唯一调用者 `UdpEndpoint.adoptGeneration` 已由 `2a007b39` 整段删除；现设计在端点创建时即绑定 owner（`UdpEndpointOptions.ConnStateOwner`） | DELETE（从接口 + 两实现中移除） | 中 |
| 4.3 | `control/session_manager.go:1132`、`:977`、`control/egress_runtime.go:143,164,180` | 整条 Go 层 TCP flow migration 链 | `02237c04`：普通 reload 由 datapath/egress runtime 的 per-packet epoch 迁移承担；`--abort` 必须直接 abort。生产已改调 `AbortGeneration`（`control_plane.go:2970`），只剩测试引用 | DELETE 或降级为测试专用（见批次 5 的先决确认） | 高 |
| 4.4 | `control/dns_runtime.go:168` | `waitDNSUpstreamsReady` 生产不可达 | 仅被 `control_plane.go:3230` 的 `WaitDNSUpstreamsReady` 调用，而后者零调用 | 见 6.x 对外 API 归属后再定 | 中 |

---

## 批次 5 — 裁决结论：两项均可删（**建议已给出，见下方依据**）

### 5.1 `hasOverlap` → **DELETE（不要恢复 `case !hasOverlap`）**

调用链：`InheritDialerHealthFrom`（`control/control_plane.go:1101-1147`，返回"是否存在 group+name 都匹配的 dialer"）→ 调用点 `cmd/run_reload_worker.go:260`、`:329`、`:447`（三条 reload 路径各一处）→ 就地传给 `newStagedReloadHandoff`（`:282`、`:351`、`:484`）→ `cmd/run.go:186` 形参 → `:197` 存字段 → `:799` 读取 → `:839 startControlPlaneRetirement` → `cmd/reload_manager.go:409,459` → `cmd/run_serve.go:79,93` `_ = hasOverlap`。

> 上一版清单漏了 `cmd/run_reload_worker.go` 的 6 处（机械扫描补出）。`InheritDialerHealthFrom` 的实际调用点全部在 `run_reload_worker.go`，不在 `run.go`。

关键证据：`b7fb496d`（2026-07-19，HEAD 祖先）**不只是删了 `case !hasOverlap: AbortConnections()`**，同一提交把 drain `canceled`/`timeout` 两个分支也从 `AbortConnections()` 改成 `AbortPendingConnections()`，并新增 `AbortPendingConnections` / `StopRoutingEpochExecution` 接口方法。即整条"retirement 会杀 established TCP"的行为被**统一移除**，是设计转向而非漏改。

机制：`AbortPendingConnections` 的文档注释写明 "preserving TCP flows already promoted into the process SessionManager"。TCP flow 在 SessionManager 中以 epoch 标记存在；普通 retirement 不调用 `AbortGeneration`，因此旧 epoch 的 flow 存活，其 egress lease 由 `egressRuntime` 引用计数（`releaseOwnerLocked`）保持到 flow 结束。因此 **dialer 是否 overlap 不再是 flow 能否存活的前提**，旧 case 失去成立条件。

两阶段语义已被测试钉死，恢复旧 case 会直接冲突：

- `cmd/run_serve_test.go:42-48,69,82`：drain-idle / canceled / timeout 三条路径都断言 **must NOT call AbortConnections (would kill active flows)**
- `cmd/run_shutdown_test.go:1564,1578`：drain 超时/取消后 "expected only AbortPendingConnections"
- `control/frozen_ad_regression_test.go:488`："timeout path must not AbortConnections / drop the held ticket"

执行：删除 `cmd/run.go:165,186,197,799,839` 的 `hasOverlap` 字段与传递、`cmd/reload_manager.go:409,459` 的参数、`cmd/run_serve.go:79,93` 的参数；`InheritDialerHealthFrom` 改为无返回值（它仍需执行 `RestoreHealthSnapshot` 与 `EnsureReloadSelectionFloor` 副作用）；把 `cmd/run_serve.go:80-89` 的 P3-9 注释改写成明确的"两阶段：drain → abort pending work"。

若产品上确实想要"无 overlap 时提前结束 drain 以加快 reload"，那应作为**新特性**显式实现并单独评估——它本质上仍要杀掉存活 flow，与当前"reload 不杀 established 连接"的承诺冲突。

### 5.2 `MigrateGeneration` 及迁移链 → **DELETE（前提结构上成立）**

调用链：`MigrateGeneration`（`control/session_manager.go:1132`）→ `FlowRuntime.migrate`（`:977`）→ `repinConnStateMapsForRollback`（`:1042`）+ `egressRuntime.transferLease`（`control/egress_runtime.go:143`）→ `dialerByIdentityLocked`（`:164`）/ `dialerIdentityEqual`（`:180`）。

补齐的两个关键事实（此前只有提交信息，现已核到代码）：

1. **唯一调用点在 `abortConnections(abortManagedTCP=true)` 内**，即只有 `AbortConnections()`（`reload --abort` 与 `abortAndClosePlane`）会走到；`AbortPendingConnections()`（普通 retirement）从不调用。由 `02237c04` 删除该调用（该提交是 HEAD 祖先）。
2. 因此"普通 reload 的 flow 连续性不受影响"**不是断言而是结构事实**：普通 reload 路径从来没有经过这条链。

`02237c04` 的理由：`--abort` 语义就是关闭 established 连接，先把"匹配的 flow"迁移到 peer generation 会让它们活过显式 abort 并继续沿用旧路由决定 —— 与 abort 契约直接冲突。

执行：删除 `MigrateGeneration`、`FlowRuntime.migrate`、`repinConnStateMapsForRollback`、`egressRuntime.transferLease`、`dialerByIdentityLocked`、`dialerIdentityEqual`，以及 `session_manager.go:956/984/993/1024` 中指向 MigrateGeneration 的注释。

注意（不要顺带删）：

- `routingEpochPeer` 仍在用（`control/routing_epoch.go:243,256`、`routing_epoch_execution.go:183`）——它服务于路由 epoch 选择器交接，与 flow 迁移无关。
- `egressRuntime` 的引用计数（`releaseOwner`/`releaseLeaseLocked`）是普通 reload 的连续性命脉，必须保留。

测试影响（改写为"abort 不做迁移"的断言）：`session_manager_scrub_gate_test.go`、`lifecycle_regression_test.go`、`frozen_ad_regression_test.go`（直接测试 `transferLease`）。

残余风险：若将来要支持"`--abort` 之外的跨 generation flow 接管"，需要重新引入该机制；当前产品语义下不需要。

---

## 批次 6 — 明确 **KEEP**：不是过时设计，删了会降级

| # | 位置 | 类别 | 理由 |
|---|---|---|---|
| 6.1 | `control/tcp.go:560-566` `Hijack`/`TsigStatus`/`TsigTimersOnly` | 接口义务 | `dnsmessage.ResponseWriter` 必需实现（`HandleWithResponseWriter_`） |
| 6.2 | `control/netkit_linux.go:20-33` `IFLA_NETKIT_*`/`NETKIT_L2,L3` | 防御/文档锚点 | `.golangci.yml` 专门为该文件关掉 `unused`，属内核头文件对照常量 |
| 6.3 | `control/kern/tproxy.c:306` `unused_lpm_type` | 文档/模板 | `ARRAY_OF_MAPS` 内层 map 模板，`bpf_utils.go:72 newLpmMap` 读其 spec；**名字误导，不是死变量** |
| 6.4 | `control/bpf_stub.go` 下 `loadBpf`/`loadBpfObjects`/`BpfMapDeleteAll`/`disablePinnedConnStateMaps`/`tuneConnStateBpfMap`/`tuneRedirectTrackMap` 等 | stub 契约 | 只在 `dae_stub_ebpf` 下"不可达"，真实构建可达或属 stub 对称实现 |
| 6.5 | `pkg/ebpf_internal/**` | 依赖副本 | cilium/ebpf 内部代码，平台/构建标签相关 |
| 6.6 | 批次 2 中标 `KEEP` 的各项 | 测试能力 | 删了是降测试能力，不是"设计更优" |
| 6.7 | `control/tcp.go:382` `RouteDialTcp` | 对外 API | `050f9b8c chore: expose the routable dialer for dae-wing (#172)` |
| 6.8 | `control/runtime_stats.go:294` `(*ControlPlane).SnapshotRuntimeStats`（方法） | 对外 API | `e6023169` 删的是**包级 Deprecated 版**，其注释明确 "prefer `(*ControlPlane).SnapshotRuntimeStats` for per-instance stats" —— 现役推荐 API |
| 6.9 | `control/node_latency.go:25,58` `TriggerLatencyChecks`/`SnapshotNodeLatencies`、`control/control_plane_dialtarget.go:42` `OnHealthCheckSuccess`、`control/netns_utils.go:106` `DeviceType` | 对外 API | 注释直接提到 GUI（`connectivity_check.go:1014` "reachable from the exported TriggerLatencyChecks API, and a fast GUI"） |
| 6.10 | `common/consts/ebpf.go` 仍在用的版本常量（`BasicFeatureVersion`、`ChecksumFeatureVersion`、`BpfLoopFeatureVersion`、`UserspaceBatchUpdate*`、`NetkitFeatureVersion` 等） | 能力目录 | 在用，勿动 |

### 待确认归属（仓内零调用，但导出面）

| # | 符号 | 现状 | 建议 |
|---|---|---|---|
| 6.11 | `control/control_plane.go:3237` `WaitDNSUpstreamsAvailable` | 包装的是**在用**的内部实现 `dns_runtime.go:193`（`:235` 调用） | 保留；若确认无仓外消费者可删包装 |
| 6.12 | `control/control_plane.go:3230` `WaitDNSUpstreamsReady` + `dns_runtime.go:168` `waitDNSUpstreamsReady` | 两者一起零调用（`85a1fc3c` 加入后未接线） | 判定为"从未接线"→ 若无仓外消费者，一并删（并入批次 3.20 类） |
| 6.13 | `control/dns_control.go:47` `ErrUnsupportedQuestionType` | 零引用（含测试），是哨兵错误 | 若无调用方要匹配该错误，可删；否则保留 |
| 6.14 | `control/anyfrom_pool.go:169` `SupportGso` | 已核对外部 `olicesx/outbound` 的 `netproxy` 接口**不含** `SupportGso` | 更可能是遗留；删除前确认无仓外/断言使用 |

## 删除操作的机械陷阱（实测得出，执行时必查）

引用审计只能证明"没有调用者"，不能证明"删这几行就编译通过、lint 通过"。批次 1 的实测暴露了两个纯机械陷阱：

1. **常量组类型继承 / `SA9004`**：`common/consts/ebpf.go` 的 `const ( TproxyMark uint32 = ...; TproxyMarkString string = ...; Recognize uint16 = ...; LoopbackIfIndex = 1 )`，删掉后两行后组内只剩一个显式类型 → staticcheck `SA9004`。**必须在同一次提交里给 `LoopbackIfIndex` 补显式类型**。（`LoopbackIfIndex` 本身是无类型常量，补类型不改变其可比性/可赋值性。）
2. **空声明块残留**：按行删除声明内容会留下 `var ()` / `const ()`；`gofmt` 不报，但 golangci-lint 的 gofmt 检查报 `File is not properly formatted`。**删除整块时必须连 `var (` / `)` 一起删**，随后跑 `make fmt`。

结论：每个删除批次都必须以 `make fmt && golangci-lint run --build-tags dae_stub_ebpf ./...` 收尾，而不是只靠引用审计。

## 验证记录

### 机械引用审计（全部批次，569 个文件）

对清单内全部符号做了跨文件类型的词元级引用扫描（`.go`/`.c`/`.h`/`.md`/`.json`/`.yaml`/`.sh`/`.service`，排除 `pkg/ebpf_internal/`、`node_modules/`、`headers/`），逐符号输出"定义处之外的引用文件"，并逐行打印全部非测试引用行（`/tmp/audit-lines.txt`、`/tmp/audit-full.txt`）。另对 `pkg/ebpf_internal/`、`node_modules/` 之外的**所有文件类型**（含 Dockerfile、脚本、CI 配置）做了同符号集扫描。

关键结论：

- 除 `unused_lpm_type`（真实 eBPF 模板，`control/bpf_utils.go:72` 读 spec、C 与生成绑定均引用）外，**没有任何删除候选出现在 `.c`/生成绑定/CI 配置里**。
- `common/consts/ebpf.go` 是手写文件，`make ebpf-sync` 只写 `common/consts/ebpf_generated.go` 与 `control/kern/ebpf_sync_defs.h`（`cmd/generators/gen_ebpf_sync/main.go:42-45`），实测 `make ebpf-sync-check` 通过 → 删除其中的常量不会破坏生成器或同步检查。
- 非 Go 文件扫到的唯一命中是 `tmp/split-dns.py`（本仓临时脚本）与文档本身，均非生产引用。

### 批次 1 实删实测（临时 worktree，已销毁）

在 `git worktree`（HEAD `ee4ce271`）上按清单 1.1–1.14 实际删除了 14 组符号（10 个文件、-109/+5 行），然后：

| 检查 | 结果 |
|---|---|
| `go build -tags dae_stub_ebpf ./...` | 通过 |
| `go vet -tags dae_stub_ebpf ./...` | 通过 |
| `go test -tags dae_stub_ebpf`（`common/consts`、`component/outbound`、`dialer`、`daedns`、`sniffing`） | 全部 ok |
| `go test -tags dae_stub_ebpf ./control/...` 失败集合 vs 干净基线 | **完全相同**（9 个失败均为环境性：需 bpffs / `bpf_bpfel.o`，与改动无关） |
| `golangci-lint run --build-tags dae_stub_ebpf ./...` | 0 issues（修掉上述两个机械陷阱后） |
| `make ebpf-sync-check` | 通过 |

### 常量实参类的全量调用点核对（批次 3）

| 项 | 生产调用点 | 测试调用点 | 结论 |
|---|---|---|---|
| `skipSniffing` | `udp_ingress_task.go:346` 传字面量 `false` | 全部 `false` | 全仓恒 `false` |
| `ignoreFixedTtl` | `dns_controller_handle.go:364,420,468` 全 `false` | 全部 `false` | 全仓恒 `false` |
| `ChooseNatTimeout` 的 `sniffDns` | `udp_ingress_task.go:195` 传 `true` | 无 | **函数体内完全未引用该参数** |
| `setExpiry` 的 `refreshCachedResponseConns` | `904`、`933` 均 `true` | 无 | 恒 `true` |
| `getOrCreateWithMark` 的 `ttl` | `udp.go:386`、`udp_endpoint_reply.go:160` 均 `AnyfromTimeout` | 均 `AnyfromTimeout` | 恒 `AnyfromTimeout` |
| `handlePktOwned`/`handlePktWithPrefetch` 的 `lConn` | 仅出现在签名行 | 测试传 `nil` | 唯一实现，体内 0 次引用 |
| `fuseStep` 的 `err` | 9 个 `return` 全为 `nil` | — | 恒 `nil`，调用点恢复分支死 |
| `indexForProto` 的 UDP 臂 | `protoIdx` 的两个调用者均传 `L4ProtoStr_TCP` | — | UDP 臂不可达（且语义错误，见 3.15） |
| `logNoAlive` 的 `strictIpVersion` | — | — | 函数体内 0 次引用 |
| `chooseProxyDialer` 的 `ctx` | — | — | 函数体内 0 次引用（仅签名） |
| `startPreparedDNSListenerWithWarmupTimeout` 的 `log` | — | — | 函数体内 0 次引用 |
| `copyDirect` 的 `record` | — | — | 两个调用点均传 `nil` |
| `CheckDnsTcp` | 仅写入（`dialer.go:277`） | 测试结构体字面量 | 全仓 0 读取 |

### 未验证的部分（明确保留）

- **行为等价性未做内核级实测**：批次 4/5 涉及 reload 生命周期，结论来自调用链可达性 + 测试断言，未在真实内核上做 reload 期间 established TCP 连续性的对照实验。
- **仓外消费者无法在仓内证伪**：批次 6.7–6.9、6.11–6.14 的导出面（`RouteDialTcp`、`SnapshotRuntimeStats`、`TriggerLatencyChecks`、`SupportGso` 等）只做了"仓内引用审计"，未验证 dae-wing/daed。
- **批次 2/3/4/5 未做实删实测**：只做了引用与调用点核对；执行时仍以每批的验证门为准。

---

## 汇总

| 批次 | 项数 | 说明 |
|---|---|---|
| 1 纯删除 | 14 组（≈30 个符号） | 可立即执行 |
| 2 测试专用 | 13 项（其中可删 5、保留 8） | 需逐项决定 |
| 3 签名收窄 | 21 项 | 每项独立提交 |
| 4 结构残留 | 4 项 | 4.1/4.2/4.3 均可删；4.4 依赖 6.12 的归属确认 |
| 5 ~~待裁决~~ | 2 项 | **已裁决：两项均删**（5.1 不恢复旧 case，5.2 前提结构成立） |
| 6 明确保留 | 14 项 | 防误删清单 |

**执行顺序建议**：批次 1 → 批次 2（先删后验测试仍绿）→ 批次 3 → 批次 4.1/4.2 → 批次 5（含 4.3）→ 最后处理 4.4 与 6.11-6.14。

## 变更影响面提示

- 批次 1 中 `common/consts/ebpf.go` 与 `component/sniffing/quic.go` 的常量删除**不影响生成文件**：`make ebpf-sync` 的输入是 `common/consts/ebpf_sync_spec.json`，与这两个文件的常量无关。
- 批次 3/4 的签名改动会波及测试夹具（`udp_pool_get_count_test.go`、`tcp_dns_frame_test.go`、`frozen_ad_regression_test.go`、`session_manager_scrub_gate_test.go`、`lifecycle_regression_test.go` 等），属于预期改动范围。
- 批次 6.7-6.9 的对外 API 若被仓外 dae-wing/daed 消费，删除会破坏下游；本次检索**无法在仓内证伪**，需下游确认。

---

## 执行记录（本次已落地）

### 已删除（提交）

| 提交 | 内容 |
|---|---|
| `061095d6` | 批次 1 全部 14 组纯删除（consts / sniffing / outbound / daedns / control） |
| `e984cf29` | 批次 2 可删 5 项（`ParseFailureCount`、`ToL4Proto`、`FillInto`、`deleteFlowFamilyMember`、`releaseFlowFamily`） |
| `3abf61b3` | 批次 3 全部可执行项（21 项中 17 项；其余 4 项见下） |
| `d8c6745a` | 批次 4.1 / 4.2 / 4.3（含批次 5.2）与批次 5.1 |
| `b1771731` | 批次 4.2 的残留 wrapper 与其不可达的 `Forget`；另修一处孤儿 `Deprecated` 标记（见文末「自检复核」） |

批次 4/5 的改动曾一度停在工作区；复核确认它们已由 `d8c6745a` 提交，不再是未提交状态。

### 批次 3 的执行边界（与初版清单的差异）

执行时把"导出符号 → 仓内零调用 ≠ 可删"这条推广到了**导出函数的常量实参**，因此以下 4 项**未执行**：

- `3.4 ChooseNatTimeout(data, sniffDns)`：**初版判断有误**。`sniffDns` 在函数体内被引用（`if sniffDns {`），并非死参数；且它是导出函数，仓外调用者可能传 `false`。保留签名。
- `3.16 GlobalOption.CheckDnsTcp`：导出字段，仓外可写；删字段会破坏下游编译。保留。
- `3.19 LookupDnsRespCache_` 的 `ignoreFixedTtl`：导出方法的形参，仓内恒为 `false` 不等于仓外恒为 `false`。保留签名（死分支随之保留）。
- `3.21 RouteDialTcpContext`：**初版"零引用"判断有误**。它被导出的 `RouteDialTcp` 调用（`control/tcp.go`），属于 6.7 对外 API 家族。保留。

其余 17 项（`skipSniffing`/`lConn`/`handleRetainedUDPEndpoint` 错误返回、`setExpiry`、`getOrCreateWithMark` 的 `ttl`、`chooseProxyDialer` 的 `ctx`、DNS listener 的 `log`、`buildRoutingKernspaceForSlot` 的返回值、`beginTCHookReplace` 的返回值、`fuseStep` 的 `err` 与死恢复分支、`newRelayCore` 的 `engine`、`markRetirementComplete` 的返回值、`copyDirect` 的 `record`、`indexForProto`/`protoIdx`、`logNoAlive` 的 `strictIpVersion`、`config.go` 的不可达 `spec.required` 分支、`ShouldAttemptSniff`）全部落地。

### 未执行（本次明确不可验证，保持原样）

- `4.4 WaitDNSUpstreamsReady` / `waitDNSUpstreamsReady`：与仓内活跃的 `WaitDNSUpstreamsAvailable` 同批引入的对外 API 对，仓外归属不可证伪。
- 批次 6 全部 KEEP 项（接口义务、防误删守卫、测试夹具、eBPF 模板）。
- `6.11-6.14` 待确认归属项。
- 批次 4/5 的内核级 reload 行为未在真实内核上验证；4.3/5.2 的"生产零调用"是静态引证结论，不是运行时结论。

### 机械陷阱的二次确认

两条陷阱在本次实删中再次出现，均已在提交中修正：

1. `common/consts/ebpf.go` 删除 `TproxyMarkString`/`Recognize` 后，同一 `const` 组只剩一个带类型常量 → `SA9004`；修正为 `LoopbackIfIndex int = 1`。
2. 整块删除后残留的 `var ()` / `const ()`：`gofmt -l` 不报，但 golangci-lint 的 gofmt 检查报 `File is not properly formatted`；必须删除整个空块后再 `make fmt`。

### 门禁结果（本次工作区终态）

- `go build -tags dae_stub_ebpf ./...`：通过
- `go vet -tags dae_stub_ebpf ./...`：通过
- `golangci-lint run --build-tags dae_stub_ebpf ./...`：0 issues
- `make ebpf-sync-check`：通过（未触碰同步结构）
- `go test -tags dae_stub_ebpf ./...`：仅剩 2 项环境性失败（`TestConnStateJanitorBoundaries`、`TestEnsureBpfPinDirReportsRealFailure`，与改动前基线逐字一致，需 bpffs）
- `make fmt`：已执行

### 残留风险（一条可证伪判据）

若仓外 dae-wing/daed 引用了批次 1/2 中删除的**导出**符号（`SelectWithExclusion`、`Dialer.Check`、`MatchSubscriptionUpstream`、`MatchNodeUpstream`、`LookupDnsRespCache`、`IncludeIp`、`FilterInput_Link`、`ErrUnexpectedField`、`ErrInvalidParameter`、`QuicFlag_*`/`QuicVersion1`、`common/consts/ebpf.go` 的常量），下游编译会失败——这类符号仓内无外部消费证据，但**不能**在仓内证伪。判据：下游 CI 若出现对应 undefined 告警，则回滚该单个符号即可，不影响其余删除。

---

## 自检复核（2026-10-05，HEAD `b1771731`）

对全仓做了一次自检（全部门禁 + 陈旧引用扫描 + 独立子代理交叉核验），与本清单相关的结论与处置如下。

### 已处置

1. **孤儿 `Deprecated` 标记（新发现，非清单原项）**：`061095d6` 删除 `FtraceFeatureVersion` 时，把它上方的 `// Deprecated: Ftrace does not support arm64 yet (Linux 6.2).` 留在了原位置，该标记因此落到活常量 `UserspaceBatchUpdateFeatureVersion` 上（`control/bpf_utils.go:138,152` 在用）。CI 只跑 `--build-tags dae_stub_ebpf`，而 `control/bpf_utils.go` 带 `!dae_stub_ebpf`，真实构建下的 2 处 SA1019 从未被门禁看见；`docs/go-1.26-modernization.md` 曾把它记为「pre-existing」。`b1771731` 删除该注释后，`golangci-lint run --default=none --enable=staticcheck ./control/...` 恢复 0 issues。
2. **批次 4.2 收尾**：`d8c6745a` 移除了接口方法与 SessionManager 实现，但漏掉了 `controlPlaneCore` wrapper（该提交信息已声称删除）。wrapper 的唯一可达副作用是同样不可达的 `udpConnStateTracker.Forget`；两者已由 `b1771731` 一并删除，tracker 的 `retain`/`BeginRelease`/`FinalizeRelease` 与三者共用的 `waiters` 握手未动。
3. **6 处删除残留注释**：`dialer_group.go`（`Select` 文档指向已删函数，且 `SelectWithExclusion` 的文档块成了孤儿）、`conn_sniffer.go`（`record` 参数已删）、`tcp_offload_linux.go`（返回值元数不符）、`dns_control_optimistic.go`（指向已删的 `LookupDnsRespCache`）、`run_shutdown_test.go`（`abort → !overlap → drain` 与同文件的两段说自相矛盾）、`session_manager.go`（`PolicyEpoch migrates mid-reload` 已不存在）。随本次文档提交一并修正。
4. **门禁基线已更新（非本次改动引起）**：本清单「门禁结果」记录的 2 项环境性失败在 `b1771731` 上不再复现——`go test -tags dae_stub_ebpf -count=1 ./...` 为 23 个包全绿、0 失败（`TestConnStateJanitorBoundaries`、`TestEnsureBpfPinDirReportsRealFailure` 均通过；本机 `/sys/fs/bpf` 仍未挂载 bpffs）。该行记录保持原样作为当时基线。

### 保留（导出面，仓内无法证伪仓外消费者）

| 符号 | 位置 | 复核结论 |
|---|---|---|
| `WaitDNSUpstreamsReady` + `waitDNSUpstreamsReady` | `control/control_plane.go:3239`、`control/dns_runtime.go:168` | 仓内零调用，与在用的 `WaitDNSUpstreamsAvailable` 同批引入但从未接线。**保留**，待下游（dae-wing/daed）确认后处理 |
| `ErrUnsupportedQuestionType` | `control/dns_control.go:47` | 含测试在内零引用；哨兵错误属导出错误契约。**保留** |
| `(*Anyfrom).SupportGso` | `control/anyfrom_pool.go:169` | 仓内零调用；已核对 pin 住的 `olicesx/outbound@fae1e14b4f48`，其 GSO 契约是 `netproxy.PacketGSOWriter` / `WriteGSO`，不含 `SupportGso`。**保留** |

### 复核命令（本次实测）

```bash
gofmt -l .
go build -tags dae_stub_ebpf ./... && go vet -tags dae_stub_ebpf ./...
go test -tags dae_stub_ebpf -count=1 ./control/... ./common/consts/...
golangci-lint run --build-tags dae_stub_ebpf ./...                               # 0 issues
golangci-lint run --no-config --default=none --enable=staticcheck ./control/...   # 真实构建，0 issues
```
