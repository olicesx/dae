---
sprint: 3
collected_by: Remy
collected: 2026-07-29
drift_vs_sprint2: zero
h5_method: bench + memprofile dual verification (Producer-phase)
---

# Sprint 3 Runtime Context

> 执行期基线环境快照 + H5 memprofile 分类证据。与 Sprint 2 对比零漂移（见 [drift-check.md](drift-check.md) §1）。

## 工具链 / Toolchain

| 项 | 值 | vs Sprint 2 |
|----|----|-------------|
| Go | go1.26.0 linux/amd64 | 同 |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 | 同 |
| clang | 18.1.3 (Ubuntu) | 同 |
| bpftool | /usr/sbin/bpftool | 同 |
| CPU | Intel(R) Core(TM) i7-14650HX | 同 |
| `.build_tags` | `trace` | 同 |
| 当前分支 | `kdae`（clean） | Sprint 1+2 共 8 perf/docs commits（e2e78563..2cd90056） |

## 构建配置（延续 F1/F2）

- **F1**（control 包须先 make ebpf 再带 -tags=trace）：延续，本 Sprint `make ebpf` EXIT=0。
- **F2**（daedns 无 bench）：本 Sprint 不涉及 daedns。
- **F3（Sprint 3 新发现）**：`go test -memprofile=X` **不可跨多包**（单文件名冲突，bench 直接失败 EXIT=1 无输出）。H5 须**逐包**跑 memprofile（见 `tmp/sprint3-mem2.sh`，每候选单包单 prof）。

## bench 调研基线（Sprint 3 H5 实测，2026-07-29）

> 命令：`go test -tags=trace -bench=. -benchmem -run='^$' -benchtime=300ms ./control/... ./component/...`（`tmp/sprint3-survey.sh`，SURVEY_EXIT=0）。原始 /tmp/s3-survey.txt。

### 所有 allocs/op > 0 热点（Sprint 3 全量扫描，按归属分类）

| Benchmark | allocs/op | B/op | 文件 | H5 归属 | Sprint 3 处置 |
|-----------|-----------|------|------|---------|--------------|
| BenchmarkWriteToBufferFlush | 60 | 3684218 | component/sniffing | **HARNESS**（net.IPv4 76.58% + net.listenTCPProto 19.15% = 95.73%；ConnSniffer.WriteTo flat=0） | **过滤**（H5） |
| BenchmarkSniffer_SniffUdp_QUICMultiPacket | 160 | 23063 | component/sniffing | PROD 59% crypto-inherent + 非密码学 Sprint-2-exhausted | 排除（§B） |
| BenchmarkSniffer_SniffUdp_QUIC | 67 | 7774 | component/sniffing | 同上 | 排除（§B） |
| BenchmarkUdpProxyDial/cache=miss | 18 | 5230 | control/udp_endpoint_pool.go | **PROD**（~30% harness + ~70% prod；bulk inherent，residual=errStrLower） | **T1**（residual） |
| BenchmarkSniffer_SniffTcp_TLS | 18 | 5294 | component/sniffing | PROD 但 sniffer-lifecycle-boundary（Sprint 2 deferred） | 排除（§C） |
| BenchmarkSniffer_SniffTcp_HTTP | 16 | 5261 | component/sniffing | 同 SniffTcp_TLS（lifecycle） | 排除（§C） |
| BenchmarkSniffTcpReadStrategy/legacy_async_read | 14 | 1112 | component/sniffing | async-read lifecycle | 排除（§C） |
| BenchmarkSniffer_SniffTcp_NotApplicable | 14 | 5185 | component/sniffing | 同 lifecycle | 排除（§C） |
| BenchmarkSniffHTTPHostHeader/legacy_scanner | 3 | 4176 | component/sniffing | legacy 弃用路径 | 排除（deprecated） |
| BenchmarkSniffHTTPHostHeader/optimized_bytes_scan | 1 | 32 | component/sniffing | 已优化（Sprint 1） | 排除（已最优） |
| BenchmarkSniffHTTPHostHeader_Extended | 1 | 32 | component/sniffing | 同上 | 排除 |
| BenchmarkUDPOrderedDispatcher.../legacy_pool/f=1024_p=8 | 0 | 8 | control | Sprint 1 A2 成果（边缘 8B） | 排除（已最优） |
| 其余 Sprint 1/2 已验证零分配热点 | 0 | 0 | — | Sprint 1 A1/A2/A4 + Sprint 2 T1 | 排除 |

## H5 分类详情（memprofile flat% 证据，`tmp/sprint3-mem2.sh`）

### §D: WriteToBufferFlush (60 allocs/op, 3.6MB) → HARNESS NOISE（H5 过滤）⭐

pprof alloc_objects top：
- `net.IPv4` flat **76.58%** — bench 每轮 net.IPv4() 构造地址
- `net.(*sysListener).listenTCPProto` flat **19.15%** — bench 每轮 net.Listen 起 TCP
- 合计 **95.73% harness**；生产 `(*ConnSniffer).WriteTo` cum 仅 2.29%（979B，io.CopyBuffer 的 dst 增长，亦是 bench bytes.Buffer dst）
- **结论**：最大热点（60 allocs/3.6MB）95%+ 为 bench 工件。**H5 过滤，不设 task**。这是 H5 价值的标杆案例：bench 表面最大 = harness 最重。

### §A: UdpProxyDial/cache=miss (18 allocs/op, 5230B) → PROD，bulk inherent，residual 可消除（T1）

pprof alloc_objects top（control.test）：
| flat% | 函数 | 归属 | 可消除？ |
|-------|------|------|---------|
| 13.69% | runUdpProxyDialBenchmark.func1 | HARNESS（bench 闭包） | — |
| 12.65% | (*UdpEndpoint).isConnectionRefused | PROD（错误路径） | **residual**：errStrLower=strings.ToLower(err.Error()) 每次 alloc 一个小写字符串 |
| 11.30% | context.WithDeadlineCause | PROD inherent | 拨号超时上下文，2 处（首次+retry） |
| 10.13% | (*UdpEndpointPool).registerEndpoint | PROD inherent | map 插入新 endpoint（dialerIndex bucket） |
| 10.12% | time.NewTimer | PROD inherent | 随 context.WithTimeout |
| 7.28% | (*UdpEndpointPool).createEndpointLocked | PROD inherent | &UdpEndpoint{} 结构体 + newDataSessionLifecycleProfile |
| 5.97% | closeQuicBenchmarkEndpoint | HARNESS（bench 拆除） | — |
| 5.60% | (*udpReuseSimulationConn).ReadFrom | HARNESS（bench mock） | — |
| 5.37% | outbound/pool.init.0.func1 | pool | — |
| 3.54% | runUdpProxyDialBenchmark.func3 | HARNESS | — |

- **HARNESS 合计**：~29%（func1+closeQuic+ReadFrom+func3）
- **PROD inherent 合计**：~41%（isConnectionRefused 部分含 errStrLower + WithDeadlineCause + registerEndpoint + NewTimer + createEndpointLocked）
- **唯一具体可消除 residual**：`errStrLower`（control/udp_endpoint_pool.go:1235）= `strings.ToLower(err.Error())`，在 `isConnectionRefused`（:1201）ICMP-refused 错误路径每次 alloc 一个小写字符串拷贝。可改为零分配大小写不敏感子串匹配（语义保持）。
- **bulk（context/timer/struct/map）inherent，Dev 须文档化为 no-op**。

### §B: Sniffer_SniffUdp_QUIC (67 allocs/op, 7774B) → 无新 in-scope

pprof flat%：hmac.New 22.95% + sha256.New 14.46% + sha256.Sum 8.06% + hkdf.Expand 7.22% + aes.New 2.98% + aes/gcm.New 1.63% + NewKeys 2.09% = **59.39% crypto-inherent**。非密码学生产点：NewPacketSniffer 5.20% / ReassembleCryptos 4.39%（T3 已优化 len<=1）/ ExtractCryptoFrameOffset 2.20% / LinearLocator.Slice 1.95% / NewLinearLocator 1.46% / sniffQuicBlock 1.46%。
- **ExtractCryptoFrameOffset / NewLinearLocator**：Sprint 2 hill-climbing 已标"经 s.quicCryptas 跨调用存活 / 装箱入 Locator 接口 = 生命周期/接口重构，超语义等价边界"。
- **NewPacketSniffer 5.20%**：sniffer 结构体生命周期，同 C（边界）。
- **结论**：59% 密码学内禀 + 非密码学全为 Sprint-2-exhausted 或 lifecycle-boundary。**无新 in-scope task**。

### §C: Sniffer_SniffTcp_TLS (18 allocs/op, 5294B) → lifecycle-boundary（排除）

pprof flat%：context.WithDeadlineCause 16.42% + context.cancelCtx.Done 6.41% + time.newTimer 4.91% = **27.74% deadline/context inherent**；readStreamOnceAsync.func1 13.42% + readStreamOnceAsync 5.61% = **19.03% async-goroutine 机制**；NewStreamSniffer **11.16% sniffer 结构体**；SniffTls 7.01% + findSniExtension 6.31% + BuiltinBytesLocator 6.07% = 19.39% TLS 解析；bytes.NewReader 5.84%。
- **主导项**（NewStreamSniffer 11% + async 19% = 30%）= Sprint 2 显式 deferred 的 **sniffer lifecycle 重构**（用户硬约束排除："sniffing 接口/生命周期调整 → 记 Sprint+1 候选"）。
- deadline/context 27% inherent。
- **结论**：主 allocs 全为 lifecycle-boundary 或 inherent。**排除**（超本 Sprint 边界）。

## Sprint 3 既有 sync.Pool（延续，本 Sprint 不新增模式）

| 池 | 文件 | Sprint 3 相关 |
|----|------|--------------|
| relayCopyBufferPool | control/tcp_copy_engine.go:18 | Sprint 2 T2 已证 harness noise，本 Sprint 不动 |
| udpDNSBufPool | component/daedns/client.go:39 | Sprint 2 T1 已用，本 Sprint 不涉及 |
| 其余 6 处 | 见 Sprint 1 runtime-context | 本 Sprint 不动 |

T1（errStrLower）**不涉及 Pool**——零分配大小写不敏感匹配，非池化。

## gate 命令速查（Sprint 3）

```bash
make ebpf                                                        # F1：EXIT=0
go vet -tags=$(cat .build_tags) ./...
go build -tags=$(cat .build_tags) ./...
go test -tags=$(cat .build_tags) ./control/... ./component/...
go test -tags=$(cat .build_tags) -race ./control/...             # T1 涉及 udp_endpoint_pool
# H5 memprofile（单包，F3）：
go test -tags=$(cat .build_tags) -bench='UdpProxyDial$' -benchmem -memprofile=/tmp/m.out -run='^$' -benchtime=300ms ./control/
go tool pprof -top -sample_index=alloc_objects -nodecount=20 /tmp/m.out
```
