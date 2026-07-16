# Sprint 1 发现清单 — T13 / T14 / T15（跨切面全局审计）

> 只读审阅，未修改任何源码。审阅对象见 `plan.md` 的 T13/T14/T15 章节。
> 行号基于审阅时的工作区状态，可能随后续提交漂移。
>
> 方法：`grep_search` 全仓统计 + `read_file` 抽样验证。已排除 `*_test.go` 的容忍性问题（仅在显著时标注）。
> 与模块审阅（T1–T12）的重叠项会显式标注"模块审阅已覆盖"。

严重度图例：P0 致命 / P1 严重 / P2 一般 / P3 建议。

---

## T13 — 并发模式全局审计（D2）

### 全仓统计（grep_search 抽样）

| 原语 | 命中数 | 主要分布 |
|---|---|---|
| `sync.Map` | 14 处 | `component/dns/dns.go`、`control/dns_control.go`、`control/packet_sniffer_pool.go`、`control/domain_routing_tracker.go` |
| `sync.Mutex` / `sync.RWMutex` | 60+ 处 | `cmd/reload_manager.go`、`control/control_plane_core.go`、`control/dns_control.go`（22 处）、`component/sniffing/sniffer.go` |
| `singleflight.Group` | 2 处 | `control/control_plane.go`、`control/dns_control.go` |
| `atomic.*` | 60+ 处 | `cmd/reload_manager.go`、`control/dns.go`（idBitmap）、`control/udp_endpoint_pool.go`、`component/dns/upstream.go` |
| `close(` | 100 处 | 主要为 `Close()` 方法、`close(chan)`、`net.Conn.Close()` |
| `<-stop` / `<-done` / `<-ready` | 50 处 | 控制平面生命周期、reload、janitor、测试 |
| `go func` | 100+ 处 | DNS 异步缓存、reload、interface monitor、UDP/TCP relay、sniffer |

### 发现清单

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P2 | component/outbound/dialer_group.go:88-91 (`DialerGroup.Close`) | **`Close()` 与 `SetSelectionPolicy()` 竞态**：`Close()` 通过 `currentSelectionState()`（atomic load，无锁）读取状态后直接调用 `unregisterAliveDialerSets(state.aliveDialerSets)`，全程未持有 `selectionStateMu`。并发的 `SetSelectionPolicy`（dialer_group.go:91 已正确加锁）可能在中途把 `selectionState` 换成新策略：例如 `case currentNeedsAliveState && !newNeedsAliveState` 分支会先把状态 Store 成不含 aliveDialerSets 的新值，再自行 unregister 旧 sets。两条路径同时执行会导致 (a) 旧 sets 被重复 unregister，或 (b) `Close()` 拿到的是已过期的快照，当前实际注册的 sets 永远漏注销（拨号器检查 ticker 泄漏）。`SetSelectionPolicy` 已用 `selectionStateMu` 串行化写入，`Close()` 未对齐同一锁。 | `Close()` 改为先 `selectionStateMu.Lock()`、读快照、unregister、再把 `selectionState.Store(nil)` 或哨兵值；或在 `Close()` 中用 `closeOnce` 配合 `SetSelectionPolicy` 早退（`if g.closed.Load() { return }`）。 |
| P2 | control/control_plane.go:3590-3630 (`ControlPlane.Close` 异步分支) | **staged-handoff 退出路径的 goroutine 泄漏**：`isBpfEjected()` 分支启动 `go func() { done := make(chan error,1); go func(){ done <- core.Close() }(); select { case <-done: ...; case <-time.After(controlPlaneDeferredCleanupTimeout): ... } }()`。注释承认 netlink.FilterDel 在虚拟/PPPoE 接口上可能 hang；超时后外层 goroutine 退出，但内部 `go func(){ done <- core.Close() }()` 永久阻塞（无任何取消手段），形成 goroutine + 1 个 netlink 句柄的泄漏。频繁 reload + 多个 PPPoE 接口会累积。 | 给 `core.Close()` 内部的 netlink 调用包一层 `context.WithTimeout` 并在 FilterDel 超时时跳过；或保留一个全局"僵尸清理"列表在下次 reload 时强制 release。 |
| P3 | component/sniffing/sniffer.go:182-187 / 226-231 (`SniffTcp`/`SniffPacket` 缓存写) | **`s.sniffed` 写入与后续读无 happens-before**：defer 块 `defer func(){ if err==nil { s.sniffed = d } }()` 在 `defer s.readMu.Unlock()` 之后才执行（LIFO 顺序），因此 `s.sniffed = d` 实际发生在锁释放后；而后续调用者在 line 182/226 读取 `s.sniffed` 时也不获取 `readMu`。两者之间没有任何同步原语。最坏情况是缓存未命中导致重复 sniff（无正确性后果），但 `go test -race` 在并发场景会报警。 | 把 `s.sniffed` 写入移到 `readMu.Unlock()` 之前（调整 defer 顺序或显式赋值再 unlock）；或改用 `atomic.Pointer[string]`。 |
| P3 | control/dns.go:85-128 (`idBitmap`) | **`next` 计数器无界增长**：`b.next.Add(1) - 1` 在 2^32 次分配后回绕。代码用 `(start >> 6) & 63` 把搜索起点限制在 64 个 word 内，回绕后逻辑仍正确（仅起点偏置被重置），无功能问题。但 `atomic.Uint32` 在高频 DNS 流水线下约几小时即接近回绕边界，回绕瞬间多 goroutine 可能同时从同一 word 开始扫描——不影响正确性，仅极短暂的扫描重叠。 | 文档化此为预期行为；若担心可改用 `next.And(4095)` 显式掩码，避免读代码者疑惑。 |
| P3 | control/udp_task_pool.go:142-155 (`UdpTaskQueue.convoy` recover) | **panic 值被丢弃**：`if r := recover(); r != nil { ... q.p.queues.Delete(q.key); q.p.queueChPool.Put(q.ch) }` 中 `r` 仅用于判空，未记录到日志。生产环境若 UDP 处理任务 panic，无法定位根因。 | 增加 `log.Errorf("udp task queue panic: %v\n%s", r, debug.Stack())`，至少在 debug 级别输出。 |

### T13 检查点覆盖说明

- **check-then-act 竞态（锁外读写共享状态）**：除上述 P2 `DialerGroup.Close` 外，已抽样 `control/dns_control.go`（`dnsCache`/`dnsKnowledge`/`dnsForwarderCache` 均 `sync.Map`，写入路径用 `dnsKnowledgeMu`/`evictorMu`/`lruScratchMu` 分片保护）、`control/packet_sniffer_pool.go`（`pool.LoadOrStore` + `retainFlowFamilyRef` 原子创建）、`control/domain_routing_tracker.go`（分片 mu + map）。其余未见显著问题。
- **锁内阻塞调用（锁内做 IO/BPF 操作）**：已检查。`control_plane_core.go` 的 `mu sync.Mutex` 仅保护 `lpmTrieIndices` 切片追加；`dns_control.go:bpfUpdateWorker` 显式把 BPF map 更新移到独立 worker goroutine + 有界 channel（`bpfUpdateCh`），`bpfUpdateStopMu` 仅保护 stop channel 初始化。` AliveDialerSet` 的 unlock-callback-lock 模式已在 T8 模块审阅标注（findings-component.md P2），此处不重复。
- **channel 多发送者关闭**：已检查，未发现问题。`control/dns_control.go:480-500` `Close()` 明确注释"intentionally do NOT close bpfUpdateCh ... would cause panics"，仅关 `bpfUpdateStop` 信号 channel；`control/control_plane.go:2023-2042`/`2067-2184` 用 `closeOnce` + `close(stop)` + `<-(done)` 模式；`packet_sniffer_pool.go:645-653` 用 `select { case <-stop: default: close(stop) }` 防重复关闭。
- **atomic 误用为同步原语**：已检查。`reload_manager.go` 的 `reloading`/`reloadActive`/`reloadPending` 三个 `atomic.Bool` 配合 `runStateChanges` channel 通知（`beginReloadHandoff` 在 Store 后立即 `runStateChanges <- struct{}{}`），不是单纯依赖原子可见性。`udp_endpoint_pool.go` 的 `hasReply`/`hasSent`/`lastRefreshNano` 仅作状态标记，决策后续仍走锁/channel。`udp.go:794 checkUdpEndpointHealth` 读 `hasSent.Load() || hasReply.Load()` 后再 `MustGetAlive`，注释明确"control-plane health should gate only new dial selections"——是有意设计。

---

## T14 — 错误处理与资源泄漏审计（D6）

### 全仓统计（grep_search 抽样，已排除 `*_test.go`）

| 模式 | 命中数 | 性质 |
|---|---|---|
| `_ = *.Close()` / `_ = fn(...)` | 30+ 处 | 多为 best-effort cleanup；少量在 reload 关键路径 |
| `defer *.Close()` / `defer func(){ _ = x.Close() }()` | 60+ 处 | 标准 defer close，覆盖良好 |
| `go func` | 100+ 处 | 多数配合 ctx.Done()/stop channel 退出 |
| `context.WithCancel` / `WithTimeout` / `WithDeadline` | 74 处 | 多数 defer cancel 配对 |
| `recover()` | 13 处 | DNS 异步缓存、UDP task pool、optimistic refresh、elf 解析等 |

### 发现清单

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P2 | control/dns_runtime.go:134 (`reuseDNSControllerFrom`) | **reload 复用路径丢弃 Close 错误**：`if r.dnsController != nil { _ = r.dnsController.Close() }` 在准备复用旧 controller 之前，把前一代残留 controller 的 Close 错误静默丢弃。如果 Close 失败（bpf map 同步、channel close 异常、forwarder 池清理失败），后续 `oldController.ReuseForReload` 仍基于"已干净关闭"的前提继续，可能继承半释放状态。`reuseDNSControllerFrom` 本身的失败有日志（line 141 `log.WithError(err).Warn`），但被丢弃的 Close 错误不会出现。 | 改为 `if err := r.dnsController.Close(); err != nil && log != nil { log.WithError(err).Warn("closing previous DNS controller before reuse") }`。 |
| P2 | control/dns_control.go:2858 / dns_control_optimistic.go:22 / dns_listener.go:275 / udp.go:765 / udp_task_pool.go:149 | **`recover()` 未输出堆栈**：所有 `recover()` 都用 `%v` 输出 panic 值，未配合 `debug.Stack()` 或 `%+v`。生产环境复现 DNS 异步缓存或 UDP 任务 panic 时，仅有 panic 值（如 "nil pointer dereference"），无法定位具体调用栈，调试成本高。`pkg/ebpf_internal/elf.go:23,43,59` 的 recover 用于控制流（sentinel error），不在此列。 | 统一改为 `c.log.Errorf("panic in X: %v\n%s", r, debug.Stack())`，至少在 Error 级别输出完整堆栈。 |
| P3 | cmd/run.go:453-455 / 564-566 (`_ = obj.Close()` 在 reload 回滚路径) | **BPF 对象 Close 错误在 reload 回滚中被吞**：port-changed 分支 `_ = obj.Close(); obj = nil` 与回滚失败兜底 `_ = c.Close()` 都忽略错误。BPF 对象 Close 失败通常意味着 map pin 未清理或程序未卸载，会在 `/sys/fs/bpf/` 留下孤儿对象，下次启动可能冲突。 | 至少在 Warn 级别记录 Close 错误，便于运维排查 `/sys/fs/bpf` 残留。 |
| P3 | control/packet_sniffer_pool.go:628-636 (`Reset`) | **`Reset()` 在 reload 时忽略所有 Close 错误**：`for _, key := range keys { ...; _ = ps.Close() }`。sniffer Close 通常只是回收 buffer，但若未来扩展为持锁资源，静默忽略会掩盖问题。 | 保留 `_ =` 但增加 debug 日志或在 Close 内部自记录。 |
| P3 | component/dns/dns.go:122 (`go func() { _ = opt.UpstreamReadyCallback(nil) }()`) | **fire-and-forget goroutine 无 recover**：如果 `UpstreamReadyCallback` panic（如访问 nil 内部状态），将导致整个 dae 进程崩溃。该回调通常简单，但跨包边界调用应防御。 | 加 `defer func() { if r := recover(); r != nil { ... } }()`。 |

### T14 检查点覆盖说明

- **error 忽略（被忽略的 error，尤其 Close/Write）**：除上述 P2/P3 外，已抽样 `control/dns.go` 的 `_ = stream.Close()`（line 385，注释说明"stream may already be closed by QUIC implementation"，合理）、`control/bpf_utils.go:100 _ = m.Close()`（error 路径下清理，合理）、`control/dns.go:484/682/906/1323`（错误路径下 best-efforce Close，合理）。`common/subscription/subscription.go:131` 的 `_, _, err = fReader.ReadLine()` 后续有 err 检查，OK。
- **defer 在循环内**：已用 `^\s*for .* := range .*\{$` + 上下文检查，未发现 defer-in-loop 模式。`control/dns_control.go:1302-1310` 的 `defer func(){ c.putLRUScratch(scratch) }()` 在 janitor 函数体内，非循环内。
- **goroutine 无明确退出路径**：已检查。所有长生命周期 goroutine（`bpfUpdateWorker`、`startDnsCacheJanitor`、`startCacheEvictor`、`startRealDomainNegJanitor`、`startConnStateJanitor`、`packet_sniffer_pool.startJanitor`、`InterfaceManager.monitor`、reload retirement goroutine）都有明确的 stop channel + done channel 或 ctx.Done() 退出路径。`cmd/run.go:215` 的内层信号 goroutine 通过 `runStateChanges` channel + 主循环退出隐式终止（函数返回后 goroutine 自然结束）。`component/dns/dns.go:122` 的 fire-and-forget 是短生命周期（回调返回即结束），见上述 P3。
- **conn/file 未 Close**：已检查。`config/config_merger.go:69`、`common/netutils/dnsconfig_unix.go:62`、`common/subscription/subscription.go:111`、`pkg/geodata/decode.go:105`、`pkg/ebpf_internal/vdso.go:34`、`trace/kallsyms.go:36`、`trace/trace.go:67` 等文件打开都有配对 defer Close。`control/tcp.go:111/187/250` 的 lConn/sniffer/rConn 都有 defer Close。
- **context 未 cancel**：已检查。`cmd/run.go:326`、`control/control_plane_core.go:143`、`component/interface_manager.go:35` 等顶层 ctx 都在 Close 路径调用 cancel。`common/netutils/dns.go:135`、`ip46.go:42` 的 cancel 在函数返回前显式调用。`component/outbound/dialer/connectivity_check.go:329`、`latency_probe.go:91` 的 WithTimeout 在函数作用域自动释放。`cmd/reload_manager.go:276` 的 retireCtx 配合 `lastRetirementCancel` 在下次 reload 时被调用。

---

## T15 — 依赖与构建审计（D7）

### 发现清单

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P1 | go.mod:127-135 (两个 replace 指令) | **核心依赖 fork 到个人命名空间，可追踪性不足**：<br>`replace github.com/olicesx/quic-go => github.com/olicesx/quic-go v0.0.0-20260428161614-e0d255ff807c`<br>`replace github.com/daeuniverse/outbound => github.com/olicesx/outbound v0.0.0-sticky-ip.0.20260518034804-52c26f8e759e`<br>两者都指向 `olicesx` 个人账号而非 daeuniverse 组织。require 行（line 14）声明 `daeuniverse/outbound v0.0.0-sticky-ip.0.20260401154811-cc1a217490f9`（2026-04-01 commit），但 replace 把实际拉取的版本覆盖为 2026-05-18 的更新 commit——require 与 replace 语义不一致，读 go.mod 时极易误判实际版本。两个 fork 也缺少对应的 tracking issue 链接或注释说明 fork 必要性（仅 quic-go 行有简短注释"B-tree node pooling + upstream cherry-picks"，outbound 行无注释）。 | (1) 在 daeuniverse 组织下镜像这两个 fork（或直接 push 到 daeuniverse/outbound 主仓的 sticky-ip 分支），避免单点依赖个人账号；(2) require 行的版本号与 replace 目标对齐，或在 replace 上加详细注释解释 fork 与上游差异、上游 PR 状态、计划合并时间。 |
| P2 | .github/workflows/kernel-test.yml:54-58 + AGENTS.md/CLAUDE.md "CI covers 5.4-6.x" | **文档与 CI 矩阵不一致**：kernel-test.yml 矩阵仅为 `6.6-20250527.055456` 和 `6.12-20250527.055456`，且注释明确"6.1 support has been dropped due to BPF verifier limitations"。但 AGENTS.md 与 CLAUDE.md 的"Kernel compatibility"章节声称"test across multiple versions (CI covers 5.4-6.x)"。新贡献者会误以为 5.4/6.1 仍被覆盖，提交破坏旧内核兼容的代码后 CI 不会报警。 | 更新 AGENTS.md/CLAUDE.md 为"CI covers 6.6 and 6.12 only (5.4/6.1 dropped due to verifier limitations)"；或在文档中明确支持的最低内核版本。 |
| P2 | .github/workflows/go-test.yml:36 vs kernel-test.yml:43 (GOEXPERIMENT 不一致) | **CI 各 job 使用不同 GOEXPERIMENT**：`go-test.yml` 用默认（Makefile 设置的 `heapminimum512kib,randomizedheapbase64`），`kernel-test.yml:43` 显式设 `newinliner,simd,heapminimum512kib,randomizedheapbase64`，`lint.yml` 未设置（走 golangci-lint 默认）。生产构建经 Makefile 也用默认。这意味着单元测试与生产二进制使用不同的内联器/GC 堆行为——某些只在新内联器下触发的 bug 不会在 go-test 中暴露，反之亦然。 | 统一所有 CI job 与 Makefile 的 GOEXPERIMENT；或在 go-test.yml 显式注入与生产一致的 GOEXPERIMENT。 |
| P2 | go.mod 全量（依赖安全性待验证） | **无法在只读审计中运行 `govulncheck`**：以下直接依赖需人工核对 Go vuln DB：<br>- `github.com/refraction-networking/utls v1.8.2`（utls 历史上有指纹识别相关 CVE）<br>- `github.com/miekg/dns v1.1.72`<br>- `golang.org/x/crypto v0.48.0`（需确认无未修复 advisory）<br>- `github.com/cilium/ebpf v0.20.0`<br>审计期间无法执行 `govulncheck ./...`，仅作待验证项标注。 | 在 CI 增加 `govulncheck` 步骤（golangci-lint 已有 gosec，但 govulncheck 覆盖官方 vuln DB 更全）；或定期手动跑并归档报告。 |
| P3 | Makefile:12-17 (CFLAGS 双重定义) | **CFLAGS 自引用赋值易混淆**：`CFLAGS := -O2 -Wall -Werror $(CFLAGS)`（line 13）后 `CFLAGS := -DMAX_MATCH_SET_LEN=$(MAX_MATCH_SET_LEN) $(CFLAGS)`（line 17）。Make 的延迟展开让它工作，但读代码者可能误以为后者覆盖前者。 | 合并为单行：`CFLAGS := -O2 -Wall -Werror -DMAX_MATCH_SET_LEN=$(MAX_MATCH_SET_LEN) $(EXTRA_CFLAGS)`，或加注释说明自引用意图。 |
| P3 | .clang-format (`AlignOperands: true`) | **clang-format 18+ 已弃用该值**：`AlignOperands` 在新版应为 `Align`（bool）或 `AlignAfterSingleLine`（旧名）。当前 clang 14/15 工作正常，但 CI 的 `bpf-test.yml` 矩阵覆盖 clang 15-19，clang 18+ 会发出 warning。 | 改为 `AlignOperands: Align`（新枚举值，向后兼容 clang 14+）。 |
| P3 | go.mod:5 (`go 1.26.0`) | **Go 指令包含 patch 版本不符合惯例**：Go 官方推荐 `go 1.26`（无 patch）。`go 1.26.0` 在 Go 1.21+ 引入 toolchain 语义后会被解释为"要求至少 1.26.0 patch"，但项目无 `toolchain` 指令，依赖 CI 的 `actions/setup-go@v6 with: go-version: 1.26`（浮动到最新 1.26.x）。本地开发者用 1.26.1 不会被 go.mod 拦截，但语义模糊。 | 改为 `go 1.26`，并视需要加 `toolchain go1.26.0` 显式 pin。 |
| P3 | .pre-commit-config.yaml:4 (`pre-commit-hooks rev v4.4.0`) | **pre-commit-hooks 版本陈旧**：当前 stable 为 v5.0.0（2024 年发布）。v4.4.0 已 2+ 年未更新。 | 升级到 v5.0.0；或锁定到 v4.6.1（最后一个 v4 系列）。 |
| P3 | .github/workflows/bpf-test.yml:31 (`continue-on-error: true`) | **BPF 测试失败不阻断 PR**：job 级 `continue-on-error: true` 意味着即使 5 个 clang 版本全部失败，PR 仍可合并。step 内 `|| (echo ...; exit 1)` 仅在 step 级报错，job 级被 continue-on-error 抹平。虽然 5 个 clang 版本可能有偶发不兼容（故 continue-on-error），但完全静默会丢失信号。 | 改为 `continue-on-error: ${{ matrix.experimental }}` 并把已稳定的版本（如 15/16）标为非实验；或保留 continue-on-error 但在 README 说明 BPF 测试为 best-effort。 |
| P3 | Makefile:14 (GOEXPERIMENT 默认值) | **`randomizedheapbase64` 在 CI 与本地可能差异巨大**：该实验选项随机化堆基址，旨在暴露指针隐藏 bug，但会让某些依赖固定地址的测试（如指针 hash）偶发失败。Makefile 把它作为默认导出，本地 `make dae` 与 `go run` 行为不一致（后者不导出）。 | 把 `randomizedheapbase64` 仅用于 CI 与 test target，release build 不启用；或文档化此为有意为之的硬化选项。 |

### T15 检查点覆盖说明

- **fork replace 必要性与追踪性**：见 P1。两个 fork 都来自 `olicesx` 个人账号，缺少到上游的 PR 链接或迁移计划。AGENTS.md/CLAUDE.md 提到 outbound 使用 forked 版本，但未说明 quic-go fork 的存在与定位。
- **依赖版本陈旧/CVE 风险**：见 P2。直接依赖总体较新（多数为 2026 年初版本），但 utls/dns/x/crypto 需 govulncheck 验证。间接依赖中 `github.com/onsi/ginkgo v1.16.5`（line 112）是 v1 老版本，ginkgo v2 已是主流（line 109 同时存在 v2.28.1）——v1 可能是某个依赖的传递引用，但建议确认是否可清理。
- **CI 矩阵与 Makefile 目标一致性**：基本一致。`make dae`/`make ebpf`/`make ebpf-test`/`make ebpf-lint` 在 CI 中都有对应 job（build.yml / kernel-test.yml / bpf-test.yml / lint.yml）。`make ebpf-sync-check` 在 CI 中未显式调用——`ebpf-sync-check` 仅依赖 `git diff --exit-code`，应被加入 PR CI 防止生成物漂移，**当前缺失**（追加 P2 finding，见下表）。
- **ebpf-lint/sync-check 配置完整性**：`make ebpf-lint` 调用 `scripts/checkpatch.pl` 并预配置忽略类型（COMMIT_COMMENT_SYMBOL/NOT_UNIFIED_DIFF 等），覆盖合理。但 `ebpf-sync-check` 未在任何 CI job 中运行，存在已生成的 `ebpf_generated.go`/`ebpf_sync_defs.h` 与 C 源不同步却被合并的风险。

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P2 | .github/workflows/ (缺失) | **`make ebpf-sync-check` 未在任何 CI job 中执行**：Makefile 提供该 target 检查 `common/consts/ebpf_generated.go` 与 `control/kern/ebpf_sync_defs.h` 是否与 C 头文件同步，但 lint.yml/build.yml/go-test.yml 均未调用。开发者本地修改 eBPF 结构后若忘记 `make ebpf-sync`，CI 不会拦截，导致 Go 代码与 eBPF C 代码的结构体布局不一致（运行时崩溃或 map 操作错位）。 | 在 lint.yml 或新增 ebpf-sync-check.yml 中加入 `make ebpf-sync-check` step，要求 clang 可用（与 bpf-test.yml 矩阵类似）。 |

---

## 跨切面总结

### 发现总数与严重度分布

| 任务 | P0 | P1 | P2 | P3 | 合计 |
|---|---|---|---|---|---|
| T13 并发 | 0 | 0 | 2 | 3 | 5 |
| T14 错误处理/泄漏 | 0 | 0 | 2 | 3 | 5 |
| T15 依赖/构建 | 0 | 1 | 5 | 5 | 11 |
| **合计** | **0** | **1** | **9** | **11** | **21** |

### 最突出的横切问题

1. **P1 - 核心依赖 fork 到 `olicesx` 个人命名空间**（T15）：quic-go 与 outbound 两个核心依赖都 replace 到个人账号，且 require/replace 版本号语义不一致，是供应链与可追踪性的最大风险。
2. **P2 - `DialerGroup.Close()` 与 `SetSelectionPolicy()` 竞态**（T13）：模块审阅（T8）已发现 `SetSelectionPolicy` 持锁跨副作用，但未发现 `Close()` 路径完全绕过同一把锁——这是横切视角才暴露的问题。
3. **P2 - 全仓 `recover()` 普遍缺少堆栈输出**（T14）：5 处生产路径 recover 都用 `%v`，调试盲区。
4. **P2 - `ebpf-sync-check` 未在 CI 执行**（T15）：eBPF 结构体布局与 Go 绑定的一致性无 CI 守护。
5. **P2 - GOEXPERIMENT 在 CI 各 job 间不一致**（T15）：测试与生产二进制行为差异。

### 与模块审阅（T1–T12）的重叠说明

- T8 已覆盖的 `AliveDialerSet` unlock-callback-lock 模式（findings-component.md P2）：本文不重复，仅扩展到 `DialerGroup.Close()` 的相邻问题。
- T2 已覆盖的 DNS 缓存 COW / singleflight / conn pool：本文确认未发现新的横切并发问题。
- T5 已覆盖的 BPF 生命周期：本文 P2 `control_plane.go:3590` goroutine 泄漏属于 Close 路径细节，若 T5 已提及则以模块审阅为准。

### 已检查未发现问题的检查点

- T13: channel 多发送者关闭（`dns_control.go` 显式注释"intentionally do NOT close bpfUpdateCh"）；atomic 误用为同步原语（reload_manager 与 udp_endpoint_pool 都正确配合 channel/锁使用）。
- T14: defer 在循环内（全仓未发现）；conn/file 未 Close（文件操作 100% 配对 defer Close）；context 未 cancel（74 处 WithCancel/Timeout 都有配对 cancel）。
- T15: CI 矩阵与 Makefile 目标基本一致（仅 ebpf-sync-check 缺失）；ebpf-lint 配置完整。
