---
sprint: 2
collected_by: Remy
collected: 2026-07-29
drift_vs_sprint1: zero
---

# Sprint 2 Runtime Context

> 执行期基线环境快照。与 Sprint 1 对比零漂移（见 [drift-check.md](drift-check.md) §1）。

## 工具链 / Toolchain

| 项 | 值 | 来源 | vs Sprint 1 |
|----|----|------|-------------|
| Go | go1.26.0 linux/amd64 | `go version` | 同 |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 | `uname -r` | 同 |
| clang | Ubuntu clang version 18.1.3 (1ubuntu1) | `clang --version` | 同 |
| bpftool | /usr/sbin/bpftool | `which bpftool` | 同 |
| CPU | Intel(R) Core(TM) i7-14650HX | bench 输出 | 同（Sprint 1 OQ4 已记） |
| OS | Windows + WSL2 (Ubuntu) | environment | 同 |

## 构建配置 / Build Config

| 项 | 值 | 备注 |
|----|----|------|
| `.build_tags` | `trace` | 同 Sprint 1 |
| 当前分支 | `kdae`（clean） | Sprint 1 5 commits：e2e78563→d203574c |
| 快速重建 | `go build -tags=$(cat .build_tags) -o dae .` | — |

## ⚠️ Sprint 2 新发现（Dev/QA 必读）

### F1: control 包构建/测试/bench **必须先生成 eBPF 绑定 + 带 build tag**

- `control/control.go:41` 的 bpf2go 指令带 `-tags "!dae_stub_ebpf"`，生成 `control/bpf_bpf*.go`。
- 这些生成文件**未提交**（gitignore 性质），`make ebpf` 的 `clean-ebpf` 会删（Makefile:81-82）。**干净 checkout 后不存在**。
- 后果：`go test ./control/...`（不带 tag）/ 无生成文件时 → `undefined: bpfObjects` build failed。
- **正确流程**（本 Sprint H1+H2 已验证）：
  1. `make ebpf`（生成 bpf_bpfeb.go/bpf_bpfel.go，EXIT=0）
  2. `go test -tags=$(cat .build_tags) ./control/...`（**必须带 -tags=trace**）
- H2 教训：H2 原始 bench 命令 `go test -bench=. ./control/... ./component/...` 漏了 `-tags`，致 control 包 build failed，只跑了 component/...。已修正为 `tmp/sprint2-bench2.sh`（带 tags）。

### F2: daedns 包无 bench 覆盖

- `component/daedns` bench 实跑 `ok 0.004s`（仅编译跑测试，无 Benchmark 函数执行）。
- T1（OQ4 client.go）目标 `sendStreamDNS`/`queryHTTPS`/`lookupType` **无 bench** → T1 无法用 bench 证非回归，须靠 race+vet+build+test + L4 安全条件人工论证。

## Sprint 2 主战场文件规模

| 文件 | 行数 | 任务 | 备注 |
|------|------|------|------|
| component/daedns/client.go | ~600+ | T1（OQ4） | udpDNSBufPool @39（同模块既有池） |
| control/tcp_copy_engine.go | — | T2（bench） | relayCopyBufferPool @18（既有池，仍分配=机会） |
| component/sniffing/*.go | — | T3（bench） | 无既有 Pool；QUIC 嗅探含密码学（Keys） |

## 既有 sync.Pool（8 处，T1/T2 须沿用其规范）

| 池 | 文件 | Sprint 2 相关 |
|----|------|--------------|
| udpDNSBufPool | component/daedns/client.go:39 | **T1 复用**（req/respBuf 沿用此模式） |
| relayCopyBufferPool | control/tcp_copy_engine.go:18 | **T2 审查**（已存在，定位未走池的分配） |
| dnsResponseBufPool | control/dns_control.go:36 | 参考（Sprint 1 A1 已用） |
| 其余 5 处 | 见 Sprint 1 runtime-context | 本 Sprint 不动 |

## bench 基线（Sprint 2 H2 实测，2026-07-29）

> 命令：`go test -tags=trace -bench=. -benchmem -run='^$' -benchtime=200ms ./control/... ./component/...`（脚本 tmp/bench-scan.sh + tmp/sprint2-bench2.sh）。原始数据 tmp/bench-raw.txt / tmp/bench-control.txt。

### T2/T3 相关热点（非零 allocs/op，本 Sprint 候选）

| Benchmark | allocs/op | B/op | ns/op | 文件 | 任务 |
|-----------|-----------|------|-------|------|------|
| BenchmarkSniffer_SniffUdp_QUICMultiPacket | 160 | 23060 | 14864 | component/sniffing | T3 |
| BenchmarkSniffer_SniffUdp_QUIC | 69 | 7797 | 5535 | component/sniffing | T3 |
| BenchmarkRelayCopyLoop_1MB | 9 | 2064572 | 478102 | control/tcp_copy_engine | T2 |
| BenchmarkRelayCopyDirect_1MB | 8 | 2064487 | 465864 | control/tcp_copy_engine | T2 |
| BenchmarkRelayCopyLoop_32KB | 4 | 32944 | 8658 | control/tcp_copy_engine | T2 |
| BenchmarkRelayCopyLoop_1KB | 4 | 1200 | 503 | control/tcp_copy_engine | T2 |

### 已验证零分配（Sprint 1 成果，Sprint 2 不设 task — H2 硬约束）

| Benchmark | allocs/op | 备注 |
|-----------|-----------|------|
| BenchmarkUDPReplyDispatcherSubmitDrain (各变体) | 0 | Sprint 1 A2 成果 |
| BenchmarkUDPOrderedDispatcherSubmitDrain (new_dispatcher 各变体) | 0 | Sprint 1 A2 成果 |
| BenchmarkUdpProxyDial/cache=hit | 0 | 缓存命中路径已最优 |
| BenchmarkGetRecoveryBackoffDuration / RecordProxyFailure / ResetStabilityCount | 0 | dialer 稳定性路径已最优 |
| BenchmarkDecryptQuic / SniffHTTPHostHeader(optimized) | 0/1 | 已高度优化 |

### 明确排除（H2 过滤后）

| Benchmark | allocs/op | 排除原因 |
|-----------|-----------|---------|
| BenchmarkDnsController_CloneCacheForReload10000 | 10081 | 冷路径（reload），Sprint 1 先例不强求；~1 alloc/entry 为 map 克隆内禀 |
| BenchmarkDnsCache_Clone / FillInto / FillIntoWithTTL | 7-11 | L2：仅 test/bench 调用，无生产 caller（YAGNI） |
| BenchmarkQuicInitialEndToEnd (各变体) | 107-112 | 涉及 fork quic-go，本 Sprint 不改 fork |
| BenchmarkKeys_PayloadDecrypt / NewKeys | 6/48 | 密码学内禀（QUIC 密钥派生），非语义可消除 |

## gate 命令速查（Sprint 2 修正版）

```bash
# ⚠️ control 包必须先 make ebpf 再带 -tags
make ebpf                                          # 生成 bpf 绑定（H1：EXIT=0）
go vet -tags=$(cat .build_tags) ./...
go build -tags=$(cat .build_tags) ./...
go test -tags=$(cat .build_tags) ./control/... ./component/...
go test -tags=$(cat .build_tags) -race ./component/daedns/... ./control/... ./component/sniffing/...  # T1/T2/T3 Pool 改动
make ebpf-test                                     # H1：本机 runs（PASS 3.187s），非 ignored
go test -tags=$(cat .build_tags) -bench=. -benchmem -run='^$' -benchtime=200ms ./control/... ./component/...  # H2：bench 非回归
```
