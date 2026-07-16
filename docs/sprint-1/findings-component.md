# Sprint 1 发现清单 — T8 / T9 / T10 / T11（component/ 全部）

> 只读审阅，未修改任何源码。审阅对象见 `plan.md` 的 T8/T9/T10/T11 章节。
> 行号基于审阅时的工作区状态，可能随后续提交漂移。

严重度图例：P0 致命 / P1 严重 / P2 一般 / P3 建议。

---

## T8 — component/outbound（D1 边界 / D2 选择策略并发 / D6 拨号器生命周期）

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P2 | component/outbound/dialer/alive_dialer_set.go:284-296 / 355-375 (`NotifyLatencyChange`) | **重入式 unlock-callback-lock 模式**：在持有 `a.mu` 的临界区内，多处执行 `a.mu.Unlock(); a.aliveChangeCallback(...); a.mu.Lock()`（用于在最佳拨号器变化时回调上层更新 BPF liveness）。释放锁到重新获取锁之间，其他 goroutine 的 `NotifyLatencyChange` 可修改 `aliveEntries`/`minLatency`。当前重新获锁后仅做日志（使用解锁前快照的 `bakOldBestDialer`），故功能正确；但模式本身脆弱——若未来在重获锁后追加依赖 `aliveEntries` 一致性的逻辑，将引入竞态。 | 将回调移出临界区（先在锁内收集回调参数快照并完成全部状态变更，释放锁后再统一触发回调）；或为回调引入独立队列（lock-free 通知 channel）。 |
| P3 | component/outbound/filter.go:38 (`regexpCache`) | **正则缓存无上限**：包级 `var regexpCache sync.Map` 缓存 `regexp2.Compile` 结果，永不淘汰。订阅链接中 name/subtag 过滤的正则模式若数量多或动态变化，缓存单调增长。单条正则编译结果内存有限，实际影响小。 | 为缓存增加 LRU 上限或按 reload 周期清理；或在 DialerSet.Close 时清理本组正则。 |
| P3 | component/outbound/dialer_group.go:99-118 (`SetSelectionPolicy`) | **持 selectionStateMu 期间触发健康检查**：`case !currentNeedsAliveState && newNeedsAliveState` 分支在持有 `selectionStateMu` 的同时调用 `d.ActivateCheck()`（可能启动拨号 ticker/发送 check 信号）与 `registerAliveDialerSets`。ActivateCheck 当前不阻塞（异步信号），未观察到死锁，但持锁跨越外部可观察副作用增加耦合。 | 将 ActivateCheck 移出锁（先在锁内决定需要激活的拨号器列表，释放锁后批量激活）。 |

### T8 检查点覆盖说明
- **dialer group 选择算法**：已检查，未发现问题。`_select`（dialer_group.go:330-377）按 policy 分派：Random 用 `GetRandExcluded`（蓄水池采样，均匀且无需 scratch buffer）；MinLatency 系列用 `GetMinLatency`（缓存 `minLatency` 热路径 + excluded 时线性回退）；Fixed 忽略 excluded（注释明确为用户显式意图优先）。`SelectWithExclusionResult` 实现 IP 版本回退（`strictIpVersion=false`）与单拨号器兜底（`len==1` 时强制 Fixed[0]），逻辑完整。
- **health check 与切换竞态**：已检查，未发现问题。`collection.Alive` 为 `atomic.Bool`；`AliveDialerSet` 用 `sync.RWMutex` 保护 `aliveEntries`/`dialerToIndex`；swap-remove 时显式更新被交换元素的 `dialerToIndex` 并 Panic 守卫自交换。`selectionState` 用 `atomic.Pointer` 无锁读取，`SetSelectionPolicy` 用 `selectionStateMu` 序列化策略切换。reload 健康继承由 `CaptureReloadSelectionFallback`/`EnsureReloadSelectionFloor`/`MarkAliveForReloadFallback` 保底，避免空集。
- **filter 逻辑**：已检查，未发现问题。`filterHit`（filter.go:62-150）支持 name/subtag 的 regex/keyword/full 多键 OR、跨 filter AND、`Not` 取反；错误键名显式返回 error。`FilterAndAnnotate` 校验 filters/annotations 长度匹配（CODE BUG 守卫）。
- **dialer 注册机制**：已检查，未发现问题。`outbound.go` 用空白导入注册所有协议（anytls/http/hysteria2/juicity/naive/shadowsocks/...）；`register.go` 的 `NewFromLinkWithProxyCacheContext` 三阶段创建（direct→DaeDNS 包装→stickyIP 包装），每阶段失败即返回 error，中间 `d`/`_p` 重赋值无泄漏。stickyIP 仅对域名地址启用（`needsStickyIpCaching` 排除 IP 字面量）。

---

## T9 — component/dns（D1 与 control/dns 重叠 / D5 解析逻辑复杂度）

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P2 | component/dns/upstream.go:200-240 (`UpstreamResolver.GetUpstream`) | **并发初始化产生重复 *Upstream 指针**：慢路径允许多 goroutine 并发 `newUpstreamFunc`（含 bootstrap DNS 解析），每个成功调用都创建新 `*Upstream` 并触发 `FinishInitCallback`（执行 `s.upstream2Index.Store(upstream, i)`）。最后一次 `state.Store` 胜出，但 `upstream2Index`（sync.Map）残留败者的指针条目，且重复 DNS 解析/回调浪费资源。代码注释承认此取舍（用重复初始化换无锁读）。 | 用 `sync.Once`/`singleflight` 去重慢路径（成功路径仍保持 `atomic.Pointer` 无锁读）；或在 Store 前用 CAS 抢占，败者直接读胜者结果。 |

### T9 检查点覆盖说明
- **request/response routing 分工**：已检查，未发现问题。`RequestMatcherBuilder`（request_routing.go）处理 QName/QType→请求上游选择；`ResponseMatcherBuilder`（response_routing.go）额外处理 Ip/Upstream→响应接受/拒绝。两者共享 `routing.NormalizedProgram.Lower` 与 optimizer 管线，但注册不同的 function parser 与 outbound 枚举（DnsRequestOutboundIndex vs DnsResponseOutboundIndex）。`NormalizedRequestRoutingProgram` 额外分类 SubscriptionRules/NodeRules/SubNodeRules（`SplitRequestRules`），强制内部 dae 选择器与 QName/QType 互斥（`classifyRequestRule` 给出明确错误）。
- **function_parser 健壮性**：已检查，未发现问题。`TypeParserFactory`（function_parser.go:14）对每个值先查 `StringToType`，再尝试 `ParseUint(v,0,16)`，均失败返回 error；不接受空值组。`addQName`/`addQType` 校验 key 白名单与 upstream 存在性。
- **upstream 容错**：见 P2。失败存 `errorSentinel` 允许重试；`New`（dns.go:67）限制 upstream 数量上限（`UserDefinedMax`），无 tag 或解析失败即报错；`CheckUpstreamsFormat` 预校验非 IP 主机名必须有 `ResolveIp46`。
- **rule split 正确性**：已检查，未发现问题。`classifyRequestRule`（request_rule_split.go:64）状态机区分 DNS/Sub/Node/SubNode/other，禁止混用，错误信息含完整规则字符串。
- **D1 与 control/dns 边界**：已检查，未发现问题。`component/dns` 负责路由程序构建与匹配（IR→matcher），`control/dns_control.go` 负责缓存/singleflight/conn pool/optimistic 等运行时编排。两者通过 `Dns` 结构（reqMatcher/respMatcher/upstream）解耦，职责清晰。

---

## T10 — component/routing（D1 与 control/routing_matcher 边界 / D5 IR 与 optimizer 正确性）

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P1 | component/routing/optimizer.go:82-106 (`MergeAndSortRulesOptimizer.Optimize`) | **合并取反(Not=true)的单函数规则改变语义**：合并条件 `mergingRule.AndFunctions[0].Not == rules[i].AndFunctions[0].Not` 允许两条同函数、同 outbound、同 Not 的单函数规则合并参数。对正向规则（Not=false）等价（OR 合并）：`f(a)->X` ∪ `f(b)->X` ≡ `f(a,b)->X`。但对取反规则不等价：`!f(a)->X` ∪ `!f(b)->X` 语义为"`!a` **或** `!b`"（任一不匹配即命中），合并后 `!f(a,b)->X` 语义为"`!(a 或 b)`" = "`!a` **且** `!b`"。两者仅当 `a`、`b` 同时匹配/同时不匹配时一致，单边匹配场景产生不同路由结果。用户若在 routing 中写两条连续取反的单域名规则并指向同一出站，会静默改变行为。 | 合并条件增加 `!mergingRule.AndFunctions[0].Not`（即仅合并 Not=false 的规则）；或对 Not=true 规则改用 AND 语义合并并文档化。建议补充 `optimizer_contract_test.go` 覆盖取反合并用例。 |
| P3 | component/routing/optimizer.go:175-186 (`DatReaderOptimizer`/`cloneParams`) | **缓存共享 *Param 指针**：`cloneParams` 仅复制切片容器，底层 `*config_parser.Param` 对象与缓存共享。注释与 `TestPostDatReaderOptimizersDoNotMutateCachedParams` 明确契约"下游 optimizer 不得修改 Param 字段"。契约靠约定维持，若新增 optimizer 误改 Param.Key/Val 会污染所有引用该 geosite/geoip 的规则。 | cloneParams 改为深拷贝 *Param（开销可接受，仅在 cache miss 的加载路径执行）；或用不可变 Param 类型在编译期强制。 |

### T10 检查点覆盖说明
- **IR 设计合理性**：已检查，未发现问题。`NormalizedProgram`（ir.go）极简（Rules+Fallback），不可变；`Lower` 用 `RulesBuilder` 注册 parser 后 `Apply`，将声明式规则降级为具体 matcher 的 match-set。`DomainSet`/`Outbound` 类型边界清晰。
- **optimizer 是否破坏语义**：见 P1（MergeAndSort 取反合并）。其余 optimizer 已检查：`AliasOptimizer`（dport→Port/dip→Ip、domain key 规范化）安全；`DeduplicateParamsOptimizer`（按 `Param.String` 去重）对正向/取反均无害；`DatReaderOptimizer`（geosite/geoip 展开+缓存）只追加 Param。
- **domain matcher 性能与正确性**：已检查，未发现问题。`AhocorasickSlimtrie`（domain_matcher/ahocorasick_slimtrie.go）按 key 类型分治：Full/Suffix→trie（后缀反转，支持 `example.com` 与 `*.example.com` 区分），Keyword→Aho-Corasick，Regex→编译后逐条。`MatchDomainBitmap` 返回位图，已匹配位短路跳过；`AddSet` 对非法字符告警跳过（Full/Suffix）。bad regex 即时 error 中止。
- **D1 与 control/routing_matcher 边界**：已检查，未发现问题。`component/routing` 提供 IR/optimizer/RulesBuilder/DomainSet 等可复用原语，`control/routing_matcher_*` 消费它们构建面向 BPF/userspace 的具体 matcher。`component/dns` 同样复用 `component/routing` 的 optimizer 管线（`DatReaderOptimizer` 等），无循环依赖。

---

## T11 — component/sniffing（D5 解析健壮性 / D6 内存与读取边界）

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P2 | component/sniffing/sniffer.go:150-170 (`readStreamOnceAsync`) | **异步读取 goroutine 在超时时泄漏至连接关闭**：`readStreamOnceAsync` 是 `SetReadDeadline` 不被支持时的回退路径。内部 `go func(){ n,err := s.buf.ReadFromOnce(s.r); ch<-... }()` 阻塞在 `s.r.Read`。当 `ctx.Done()`（deadline）触发，外层 goroutine 置 `dataError` 并 `close(ready)` 返回，但内层读 goroutine 仍阻塞。外层 `<-ctx.Done()` 分支尝试 `s.conn.SetReadDeadline(time.Unix(1,0))` 解除阻塞，但该分支恰在"SetReadDeadline 不支持"时执行，调用同样失败（错误被忽略）。内层 goroutine 直到 `ConnSniffer.Close`→`s.Conn.Close()` 才随连接读取返回而退出。属"连接生命周期内有界"的瞬时泄漏，非永久泄漏，但每个超时流式嗅探会残留一个 goroutine+栈。 | 在 `readStreamOnceAsync` 的 `ctx.Done` 分支记录 pending 读 goroutine，`Sniffer.Close` 时若仍在阻塞则尝试关闭 reader 或置标志让其退出；或在文档中明确该回退路径的 goroutine 生命周期绑定 conn。 |
| P3 | component/sniffing/quic.go:118-128 (`sniffQuicBlock` 解密) | **对未确认数据执行 QUIC 解密**：在仅校验 header form + Initial 类型（version/fixed-bit 故意放宽以兼容多实现）后即对 `buf` 做 `quicutils.DecryptQuic_`（HKDF+AES）。恶意/畸形 Initial 包可触发完整密码学运算后才判定 NotApplicable。存在 CPU 放大面，但这是 QUIC 嗅探的固有代价（必须解密才能取 SNI），且 `quic_fuzz_test.go` 覆盖。 | 可加 connId 白名单/速率限制减少无关解密；属已知取舍。 |

### T11 检查点覆盖说明
- **协议解析边界检查（OOB/畸形包）**：已检查，未发现问题。三个解析器均严格边界检查：
  - **TLS**（tls.go）：用 `quicutils.Locator` 抽象（`Range`/`At`/`Slice`/`Len`，越界返回 error），每个长度派生的 `boundary` 都有 `if search.Len() < boundary` 守卫；SNI 扩展遍历用 `iNextField > search.Len()` 守卫，`extLength < sniLen+2` 守卫嵌套长度。无裸切片越界。
  - **HTTP**（http.go）：`bytes.Cut`/`Index` 安全；首字节 `unicode.IsPrint` 守卫；方法名截断到 12 字节校验。
  - **QUIC**（quic.go）：每个字段（dstConnId/srcConnId/token/length/packetNumber）读取前均 `if len(buf) < boundary`；varint 用 `BigEndianUvarint` 返回 error；包号保护用 `pool.Get` 缓冲 + defer 原位恢复。
- **QUIC initial 解析**：已检查，未发现问题。`IsLikelyQuicInitialPacket`（quic.go:31）仅检 header form+Initial 类型（注释说明 version/fixed-bit 放宽兼容）；`SniffQuic` 支持多 block 重组（`quicCryptos`/`quicNextRead` 跨包累积），`ReassembleCryptos` 处理 crypto frame 偏移重组，`CompactPacketState` 在会话不再需要握手缓冲时释放。
- **conn sniffer relay 内存**：已检查，未发现问题。`relayBufPool`（sync.Pool，32KB/块）复用；`WriteTo` 优先 splice（`io.Copy` 探测 `*net.TCPConn`），回退 `io.CopyBuffer`；`ReadFrom` 用 `copyDirect` 显式缓冲避免 `net.TCPConn.ReadFrom` 的隐藏堆分配；`TakeRelayPrefix` 文档明确返回切片仅限 relay goroutine 同步立即使用；`Close` 用 `closeMu.Do` 释放 buf 与 quicPlaintexts。
- **fuzz 覆盖**：已检查，覆盖良好。`tls_fuzz_test.go`/`quic_fuzz_test.go`/`http_fuzz_test.go` 均存在，含空、截断、全零、畸形长度等种子；`benchmark_test.go` 覆盖性能；`conn_sniffer_*_test.go` 覆盖 relay 路径。

---

## 汇总

- **发现总数**：8（T8×3、T9×1、T10×2、T11×2）
- **P0**：0　**P1**：1　**P2**：3　**P3**：4
- **最突出问题**：T10 `MergeAndSortRulesOptimizer` 合并取反规则改变 OR→AND 语义（P1，影响取反连续单函数规则的路由正确性）；T9 `GetUpstream` 并发初始化重复指针（P2，资源浪费）。
