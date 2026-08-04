---
sprint: 6
doc: runtime-context
owner: Remy
created: 2026-08-04
source: drift-check §0 + PROJECT_BRIEF §6 + Sprint 5 H8 bench 基线
---

# Sprint 6 Runtime Context — 稳定性 / bug fix 收割

> Producer 阶段冻结的运行时基线。Dev 实现前必读；QA 验证以此为前后对照基准。
> ⚠️ race/ebpf/bench 三维度**未权威验证**（drift-check §0），标「基线待 Dev 补跑」。

## 工具链基线

| 项 | 值 | 漂移（vs Sprint 5） |
|----|----|-----|
| Go | go1.26.0 linux/amd64 | ❌ 无 |
| clang | 18.1.3 (Ubuntu) | ❌ 无 |
| bpftool / make | 就绪 | ❌ 无 |
| kernel | 6.18.33.2-microsoft-standard-WSL2 | ❌ 无（同 WSL 实例） |
| `.build_tags` | `trace` | ❌ 无 |
| eBPF lib | cilium/ebpf v0.20.0 | ❌ 无 |
| **fork 依赖** | quic-go/outbound **多次 bump**（GSO/buffer race/HKDF/pool-overflow） | ✅ **变更**（既成事实，Sprint 6 不改 fork） |

## 游离 commit 验证状态（基线快照）

> 来源：drift-check §0。23 个 commit（722b123b..HEAD），59 files / +8608 / -7018。

| 验证维度 | 状态 | 基线值 | T1 目标 |
|----------|------|--------|---------|
| `go vet ./...` | ✅ EXIT=0 | — | 复核 clean |
| `go test ./...` | ✅ EXIT=0（19+ 包 ok） | — | 复核 clean |
| `go test -race ./...` | ⚠️ **待测** | — | clean（23 commit 含并发改动） |
| `make ebpf` | ⚠️ **待测** | — | EXIT=0 |
| `make ebpf-test` | ⚠️ **待测** | — | PASS（L16/L17：build-tag 门控） |
| `make ebpf-lint` | ⚠️ **待测** | — | clean |
| `make ebpf-sync-check` | ⚠️ **待测** | — | pass |
| sniffing bench allocs | ⚠️ **待测**（非回归对照见下） | Sprint 5 H8 基线 | 不回归 |

## bench 非回归对照基线（Sprint 5 H8 后）

> Sprint 5 T3 H8 首次应用后的 deadline-sync bench 数据，作为 Sprint 6 非回归对照。
> ⚠️ `component/sniffing/sniffer.go` 被游离 commit `28872b0b` 改过（nil buf guard after Close），正常路径 bench 应不变（guard 只影响 Close 后路径），但须实测确认。

| Benchmark | Sprint 5 H8 基线 allocs | Sprint 5 H8 基线 ns/op | 备注 |
|-----------|------------------------|----------------------|------|
| SniffTcp_HTTP | 5 (224 B) | — | deadline-sync 基线 |
| SniffTcp_TLS | 6 (240 B) | — | deadline-sync 基线 |
| SniffTcp_NotApplicable | 3 (168 B) | — | deadline-sync 基线 |
| sniffHTTPHostHeader Extended | 1 (32 B) | 80.91 | Host string inherent |
| sniffHTTPHostHeader NoHost | 0 | 32.82 | 零分配 |

> 非回归判据：allocs/op 不增（H8 deadline-sync 路径）。ns/op 允许微基准噪声波动（±15%）。refactor 后若 allocs 变化须记录并分析原因（非自动判回归）。

## 代码结构变化（既成事实，Dev 必读）

> 巨型文件已被游离 commit 拆分。Sprint 6 验证须在新结构上进行。

| 原文件 | 拆分后 | 拆分 commit |
|--------|--------|------------|
| `cmd/run.go` | `cmd/run_{config,controlplane,reload,serve}.go` | `cf1db3ad` |
| `control/dns_control.go` (3635 行) | `control/dns_controller_{bpf,cache,forwarder,handle,response,runtime}.go` (6 文件) | `34c88f99` |
| `control/udp_endpoint_pool.go` (2557 行) | `control/udp_endpoint_{lifecycle,reply,watcher}.go` + `udp_runtime.go` | `a9895907` |
| `control/control_plane.go` (embedded structs) | `control/{event_ringbuf,listener_runtime,real_domain_runtime,routing_epoch_runtime}.go` | `ddb1bd01` |

**新增测试（随 bug fix 加入）**：
- `control/dns_truncate_test.go`（随 `1ddfd8fb` dns TC bit fix）
- `control/group_override_option_test.go`（随 `eee7c88b` preserve dae DNS fix）

**删除**：
- `control/tcp_copy_test_helpers_test.go`（refactor 过程移除——Sprint 5 KEEP 列表中的 helper，现为既成事实）

## 漂移登记

| 漂移项 | 性质 | Sprint 6 处置 |
|--------|------|--------------|
| 巨型文件拆分 | 既成事实（S1-5 deferred 被做） | 不重做；新结构上验证 |
| fork 多次 bump | 既成事实 | 不改 fork；验证兼容性 |
| bug fix × 5 | 既成事实 | 验证正确性 + OQ-S6-1 评估同类 |
| `tcp_copy_test_helpers_test.go` 删除 | 既成事实 | 不恢复（refactor 合理移除） |
