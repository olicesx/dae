---
sprint: 1
collected_by: Remy
collected: 2026-07-29
---

# Sprint 1 Runtime Context

> 执行期基线环境快照，供 Dev/QA 复现与 benchmark 对照。

## 工具链 / Toolchain

| 项 | 值 | 来源 |
|----|----|------|
| Go | go1.26.0 linux/amd64 | `go version` |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 | `uname -r` |
| clang | Ubuntu clang version 18.1.3 (1ubuntu1) | `clang --version` |
| clang 路径 | /usr/bin/clang | `which clang` |
| bpftool | /usr/sbin/bpftool | `which bpftool` |
| make | /usr/bin/make | `which make` |
| OS | Windows + WSL2 (Ubuntu) | environment |

## 构建配置 / Build Config

| 项 | 值 |
|----|----|
| `.build_tags` | `trace` |
| 当前分支 | `kdae`（feature branch ✅） |
| 快速重建 | `go build -tags=$(cat .build_tags) -o dae .` |
| 完整构建 | `make dae`（含 eBPF 编译） |

## go.mod 关键 replace（fork 依赖，本 Sprint 不改 fork 代码）

| 模块 | replace 到 | go.mod 行 |
|------|-----------|-----------|
| `github.com/olicesx/quic-go` | `github.com/olicesx/quic-go v0.0.0-20260428161614-e0d255ff807c` | 116 |
| `github.com/daeuniverse/outbound` | `github.com/olicesx/outbound v0.0.0-sticky-ip.0.20260728062433-286c1c1b72ea` | 122 |
| `github.com/cilium/ebpf v0.20.0` | （注释，未启用） | 118 |

## 热点文件规模（本 Sprint 主战场）

| 文件 | 行数 | 方向 |
|------|------|------|
| control/dns_control.go | 3635 | A1 |
| control/udp_endpoint_pool.go | 2557 | （参考，本 Sprint 不直接改） |
| control/dns.go | 1445 | A1 |
| control/routing_matcher_builder.go | 949 | A4 |
| component/daedns/router.go | 753 | A5 |
| control/dns_cache.go | 695 | A3 |
| control/udp_ordered_dispatcher.go | 545 | A2 |
| control/udp_reply_dispatcher.go | 446 | A2 |
| control/udp_task_pool.go | 357 | （参考） |
| control/routing_matcher_userspace.go | 277 | （参考） |
| control/udp_ingress_batch.go | 123 | A2 |
| control/kern/tproxy.c | 3328 | B1/B2 |

## 既有 sync.Pool（8 处，优化须沿用其规范）

| 池 | 文件:行 |
|----|---------|
| responseSlotPool | control/dns.go:44 |
| udpEndpointReplyObjects | control/udp_endpoint_pool.go:771 |
| queueChPool | control/udp_task_pool.go:228 |
| dnsResponseBufPool | control/dns_control.go:36 |
| relayCopyBufferPool | control/tcp_copy_engine.go:18 |
| tcpDnsBufPool | control/tcp.go:422 |
| tcpSniffPrefetchBufPool | control/tcp_sniff_policy.go:37 |
| udpDNSBufPool | component/daedns/client.go:39 |

## eBPF 数据平面信号（tproxy.c）

- map 操作总数：35（`bpf_map_lookup_elem` 28 + `update` 7）
- `conn_state_map` lookup 站点：1837/1907/1956/2046（B2 候选，按 D2 验证 clang DCE 后再定）
- scratch map（per-CPU，决策 D2 不合并）：parse_ctx_scratch(1051/1512/2090/2528)、pkt_scratch(2198/2935)、wan_egress_route_scratch(2632/2798)
- static/SEC 函数约 90

## gate 命令速查

```bash
go vet ./...
go build -tags=$(cat .build_tags) ./...
go test ./control/... ./component/...
go test -race ./control/... ./component/...        # D1: Pool 改动必跑
make ebpf-lint                                       # B 任务：零 warning
make ebpf-sync-check                                 # B 任务：Go 绑定一致
make ebpf-test                                       # ci_gate，本机 ignored
```
