---
sprint: 4
collected_by: Remy
collected: 2026-07-29
drift_vs_sprint3: zero_technical (constraint_policy intentionally changed)
h7_method: pprof CPU profile (new dimension) + H5 memprofile (lifecycle classification)
h5_method: bench + memprofile dual verification (carried from Sprint 3)
--- 

# Sprint 4 Runtime Context

> 执行期基线环境快照 + H7 CPU profile 调研（新方法论）+ H5 memprofile lifecycle 候选分类。
> 与 Sprint 3 对比零技术漂移（见 [drift-check.md](drift-check.md) §1）；唯一计划内变更 = 约束解除（lifecycle_refactor_allowed）。

## 工具链 / Toolchain

| 项 | 值 | vs Sprint 3 |
|----|----|-------------|
| Go | go1.26.0 linux/amd64 | 同 |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 | 同 |
| clang | 18.1.3 (Ubuntu) | 同 |
| bpftool | /usr/sbin/bpftool | 同 |
| CPU | Intel(R) Core(TM) i7-14650HX | 同 |
| `.build_tags` | `trace` | 同 |
| 当前分支 | `kdae` | Sprint 1-3 共 9 perf/docs commits |

## 构建配置（延续 F1/F3）

- **F1**（control/sniffing 包须先 make ebpf 再带 -tags=trace）：延续，本 Sprint `make ebpf` EXIT=0。
- **F3**（-memprofile/-cpuprofile 不可跨多包）：延续，本 Sprint 仅 sniffing 单包，无跨包问题。
- **F4（Sprint 4 新增）**：`-cpuprofile` 与 `-memprofile` 不可同一次 bench 跑（sample 冲突）；CPU 与 mem 分两次跑（见 survey §3/§4/§5）。

## §H7 CPU Profile（新维度，Producer 阶段首次引入）⭐

> 命令：`go test -tags=trace -bench=. -cpuprofile=/tmp/s4-cpu-sniff.prof -run='^$' -benchtime=3s ./component/sniffing/`（`tmp/sprint4-survey.sh` §3，CPU_EXIT=0）。原始 /tmp/s4-cpu-sniff.prof。

### CPU top 25（cumulative，runtime + 应用混合）

| flat% | flat | cum% | cum | 函数 | 归类 |
|-------|------|------|-----|------|------|
| 0% | — | 46.20% | 48.32s | testing.(*B).runN | HARNESS（bench 驱动） |
| 0.54% | 0.56s | 14.20% | 14.85s | runtime.mallocgc | **GC（分配驱动）** |
| 0% | — | 27.26% | 28.51s | runtime.gcBgMarkWorker | **GC mark** |
| 1.40% | 1.46s | 11.70% | 12.24s | **sniffing.sniffHTTPHostHeader** | **APP（HTTP 嗅探）** |
| 4.16% | 4.35s | 11.68% | 12.22s | runtime.scanObjectsSmall | GC mark |
| 0.23% | 0.24s | 9.49% | 9.92s | **sniffing.(*Sniffer).SniffTcp** | **APP（TCP 嗅探 lifecycle）** |
| 2.16% | 2.26s | 7.55% | 7.90s | bytes.Index | APP（子串匹配） |
| 6.92% | 7.24s | 6.92% | 7.24s | runtime.futex | runtime（调度） |
| 0.27% | 0.28s | 6.82% | 7.13s | **sniffing.NewStreamSniffer** | **APP（sniffer 构造 lifecycle）** |
| 0.048% | 0.05s | 6.31% | 6.60s | **sniffing.(*Sniffer).SniffQuic** | **APP（QUIC 嗅探 lifecycle）** |

### H7 关键洞察：CPU 与 alloc 热点收敛

**GC 主导 CPU 时间**：gcBgMarkWorker 27.26% + mallocgc 14.20% + scanSpan/scanObject ~23% = **约 41-50% CPU 花在 GC/mark**。GC 压力的根因是**分配**（每连接 sniffer 构造 + async goroutine + Locator 装箱）。

**推论（H7 价值）**：Sprint 1-3 用 bench/memprofile（H5）只看「分配次数」。H7 CPU profile 揭示这些分配**同时是 CPU 热点**（因为触发 GC）。因此 lifecycle 重构（砍每连接分配）将**同时**降低 alloc 和 CPU GC 时间——这是 bench/memprofile 单独无法证明的收益闭环。

**应用热点 top（排除 runtime/GC）**：sniffHTTPHostHeader cum 11.70% / SniffTcp cum 9.49% / NewStreamSniffer cum 6.82% / SniffQuic cum 6.31% / bytes.Index cum 7.55%。前 4 个均落在 sniffer lifecycle 路径，验证本 Sprint 主题（lifecycle refactor）选向正确。

> ⚠️ 与风险预判 #3 对照：用户预判「CPU 热点与 alloc 热点可能不重合」。实测**重合**（GC 驱动）——这正是 H7 的发现价值：用数据否定一个合理但错误的预判。

## §H5 memprofile — SniffTcp_TLS（lifecycle 候选 C，TCP 路径）

> 命令：`go test -tags=trace -bench='Sniffer_SniffTcp_TLS$' -memprofile=/tmp/s4-mem-tls.prof -run='^$' -benchtime=300ms ./component/sniffing/`（survey §4，EXIT=0）。alloc_objects top 20。

| flat% | 函数 | lifecycle 归类 | 可重构？ |
|-------|------|---------------|---------|
| 16.04% | readStreamOnceAsync.func1 | **POOLING**（async goroutine 闭包 + readResult channel 每次构造） | **T1** |
| 11.82% | context.WithDeadlineCause | inherent（deadline 机制） | ❌ inherent |
| 11.31% | NewStreamSniffer | **POOLING**（Sniffer struct + buf 每连接构造） | **T1** |
| 10.38% | BuiltinBytesLocator.Slice | **INTERFACE 收敛**（Locator 装箱） | **T2** |
| 8.35% | time.newTimer | inherent（随 deadline） | ❌ inherent |
| 7.14% | pool/bytes.NewBuffer | POOLING（buf，随 NewStreamSniffer） | **T1** |
| 6.49% | SniffTls | TLS 解析（含 Locator 调用） | 部分 T2 |
| 5.90% | pool/bytes.growSlice | buf 增长 | T1 关联 |
| 5.84% | net.SplitHostPort.func1 | harness（bench 构造地址） | ❌ harness |
| 5.19% | bytes.NewReader | TLS 解析 reader | 部分 T2 |
| 3.62% | context.(*cancelCtx).Done | inherent（deadline cancel） | ❌ inherent |

- **readStreamOnceAsync cum 28.98%**（func1 16% + channel 机制）：每次 readStreamOnce 在 async 路径 spawn 一个 goroutine + 一个 buffered readResult channel。**池化候选**：goroutine 复用 + channel 复用。
- **inherent 合计**（deadline/context/timer/cancel）：~24%，无法消除（超时语义）。

## §H5 memprofile — SniffUdp_QUIC（lifecycle 候选 B，UDP 路径）

> 命令：同上，bench='Sniffer_SniffUdp_QUIC$'（survey §5，EXIT=0）。alloc_objects top 20。

| flat% | 函数 | lifecycle 归类 | 可重构？ |
|-------|------|---------------|---------|
| 21.95% | hmac.New | **CRYPTO inherent** | ❌ inherent |
| 17.71% | outbound/pool.Put | **POOLING 关联**（QUIC buf churn，NewPacketSniffer 每包构造 buf） | **T1**（UDP 路径） |
| 15.12% | sha256.New | CRYPTO inherent | ❌ inherent |
| 7.35% | sha256.Sum | CRYPTO inherent | ❌ inherent |
| 6.30% | hkdf.Expand | CRYPTO inherent | ❌ inherent |
| 3.50% | NewPacketSniffer | **POOLING**（packet sniffer struct + buf 每包构造） | **T1**（UDP 路径） |
| 3.11% | ExtractCryptoFrameOffset | **跨调用存活**（每帧 alloc CryptoFrameOffset struct） | **T3** |
| 2.88% | aes.New | CRYPTO inherent | ❌ inherent |
| 2.63% | pool.init.0.func1 | pool | — |
| 2.26% | ReassembleCryptos | **跨调用存活**（merged slice + CryptoFrameOffset structs） | **T3** |
| 2.26% | pool/bytes.NewBuffer | POOLING（随 NewPacketSniffer） | **T1** |
| 2.17% | LinearLocator.Slice | **INTERFACE 收敛**（Locator 装箱） | **T2** |
| 2.10% | NewKeys | CRYPTO inherent | ❌ inherent |
| 2.07% | NewLinearLocator | **INTERFACE 收敛**（装箱入 Locator 接口） | **T2** |
| 1.70% | findSniExtension | TLS 解析 | — |

- **CRYPTO inherent 合计**：hmac 21.95% + sha256 15.12%+7.35% + hkdf 6.30% + aes 2.88% + gcm 1.21% + NewKeys 2.10% ≈ **57%**（与 Sprint 3 的 59% 一致，确证不可优化）。
- **pool.Put 17.71%**：QUIC 嗅探的高 buf churn——NewPacketSniffer 每包 `pool.GetBuffer()` + 后续 Put。UDP 每包一个 packet sniffer，pool.Put 频繁。**T1 UDP 路径池化候选**。

## Lifecycle 候选分类汇总（task DAG 输入）

| 候选 | 路径 | flat%（mem） | CPU cum% | 重构类型 | 对应 task |
|------|------|------------|---------|---------|----------|
| NewStreamSniffer struct + buf | TCP | 11.31% + 7.14% | 6.82% | 对象池化（Sniffer pool） | T1 |
| readStreamOnceAsync goroutine + channel | TCP | 16.04% (func1) | （含于 SniffTcp 9.49%） | 对象池化（goroutine/channel 复用） | T1 |
| NewPacketSniffer struct + buf (pool.Put churn) | UDP | 3.50% + 17.71% | （含于 SniffQuic 6.31%） | 对象池化（packet sniffer pool） | T1 |
| BuiltinBytesLocator.Slice / NewLinearLocator / LinearLocator.Slice | TCP+UDP | 10.38% / 2.07% / 2.17% | — | 接口收敛（减少 Locator 装箱） | T2 |
| ExtractCryptoFrameOffset / ReassembleCryptos | UDP | 3.11% / 2.26% | — | 跨调用存活（CryptoFrameOffset 经 s.quicCryptos 复用） | T3 |

## 既有 sync.Pool（sniffing 包，重构参考）

| 池/复用机制 | 位置 | Sprint 4 关系 |
|------------|------|--------------|
| pool.GetBuffer() / outbound pool | NewStreamSniffer/NewPacketSniffer | buf 已池化，但 Sniffer struct 本身未池化（T1 目标） |
| 无 goroutine/channel pool | readStreamOnceAsync | **T1 新增**（async 机制当前每调用新建） |

## gate 命令速查（Sprint 4）

```bash
make ebpf                                                        # F1：EXIT=0
go vet -tags=$(cat .build_tags) ./...
go build -tags=$(cat .build_tags) ./...
go test -tags=$(cat .build_tags) ./component/sniffing/... ./control/...
go test -tags=$(cat .build_tags) -race ./component/sniffing/...  # T1/T2/T3 涉及 sniffer 并发
# H7 CPU profile（F4：与 memprofile 分跑）：
go test -tags=$(cat .build_tags) -bench=. -cpuprofile=/tmp/s4-cpu.prof -run='^$' -benchtime=3s ./component/sniffing/
go tool pprof -top -cum -nodecount=20 /tmp/s4-cpu.prof
# H5 memprofile（F3：逐 bench）：
go test -tags=$(cat .build_tags) -bench='Sniffer_SniffTcp_TLS$' -memprofile=/tmp/m.out -run='^$' -benchtime=300ms ./component/sniffing/
go tool pprof -top -sample_index=alloc_objects -nodecount=20 /tmp/m.out
```
