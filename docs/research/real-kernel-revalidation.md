# 真实内核复测清单（待环境就绪执行）

> ⚠️ **复测已完成（2026-08-15，labs.lan：Azure VM，AMD Ryzen 7 3800X 4 核，内核 6.17.0-1011-azure）。**
> 结论：**批写（sendmmsg）在真实内核同样无收益**——每包 UDP 处理成本（~3.6-4.6μs）主导，
> sendmmsg 内核路径 = N×单包路径（微基准线性验证）。dae 用户态 UDP 转发上限 ≈ 200-300K pps
> （此环境），WSL2 的 96% 丢包是同一机制的真实放大版（每包 11μs vs 4.6μs）。完整数据见下文
> "实测结果（已完成）"。以下原始清单保留供其他环境复测。

> 目的：量化 WSL2 无法验证的两项收益/风险——① sendmmsg 批写（真实内核 syscall 便宜，
> 预期 ~5x 写路径收益）② 批写同步 flush 的阻塞率（WSL2 慢 sendmmsg 下恶化，真实内核应无碍）。
> 依据：`udp-p8-collapse-root-cause.md`（根因与 WSL2 局限）与以下提交。

## 待复测改动

| 仓库 | 提交 | 内容 |
|---|---|---|
| outbound | a3b54a6 | netproxy.PacketBatchWriter + direct.WriteBatch（sendmmsg）+ socks5.WriteBatch |
| outbound | 942b5a4 | WriteBatch scratch 池化（分配 -94%） |
| dae | ac556546 | UdpEndpoint 批聚合器（32 包 / 1ms 窗） |
| dae | d2085352 | task 闭包 owned 化（总分配 -62%/-60%） |
| dae | e30de886 | Symmetric 流 dial target String 复用 |

## 环境要求
- Linux 物理机或 KVM/VM（**非 WSL2**），内核 ≥ 5.15（建议 6.x），root
- Go 1.26（GOTOOLCHAIN=auto + GOPROXY）、clang（eBPF 构建）、iperf3
- 构建：`go mod edit -replace` 本地 fork（outbound/quic-go），`make ebpf && make dae`（参考 ab_bench/00_setup.sh 的 L25 教训：replace 必须生效，`go version -m` 验证）

## 步骤 1：微基准（30 分钟，最先做——不受环境拓扑影响）
```bash
cd outbound && go test ./protocol/direct/ -run '^$' \
  -bench 'BenchmarkDirectWrite' -benchmem -count 5
```
- **判据**：单包 write ~0.5-1μs（非 WSL2 的 11μs）；批 32 sendmmsg **每包 ≤ 单包的 40%**
  （预期 0.2-0.3μs/包，~5x）；allocs ≤ 242B/32
- 若批 32 无明显收益（每包 ≈ 单包）→ 内核/网卡路径有每包硬成本 → 批写收益存疑，需汇报

## 步骤 2：socks 路径 e2e（真实 honk P8 拓扑）
拓扑（复用 hp_test.sh 模式）：netns sender（8 流饱和）→ dae tproxy（dport 5201 → socks5）
→ socks_proxy（127.0.0.1:1080）→ receiver（loopback :5201，探针测 per-flow loss/reorder）

A/B：`dae-core-base`（e628af76 之前）vs `dae-core`（HEAD 含批写）各 ≥3 轮交替：
- **判据（吞吐/丢包）**：receiver lost% 显著下降（WSL2 是 92-96%，真实内核基线未知——
  记录基线后对比 A/B 相对变化）；proxy relayed 计数 = 端到端验证
- **判据（CPU）**：pprof 的 Syscall6 占比：写路径应从 ~30%（若有）降到 ~3% 以下；
  gctrace=1 的 GC cycles/STW 不劣化
- **判据（延迟/阻塞）**：`-count-only` 模式下 dae CPU 无异常高（同步 flush 阻塞率 =
  sendmmsg 耗时/批窗 1ms——真实内核 ~10μs/批 → 1% 无感）；若观察到 worker 停顿
  （dae 处理率骤降），回退评估异步 flush 设计

## 步骤 3：direct 路径 e2e（回归对照）
- 相同拓扑但 fallback direct（不经 dae 用户态）——确认 eBPF 数据面无回退（对照 ab_bench
  T2 历史值：P1 1000Mbps 无丢 / P8 ~12.4Gbps 32-33% 丢为 WSL2 值，真实内核基线重新记录）

## 步骤 4：分配回归（10 分钟）
```bash
go test ./control/ -run 'TestUdpIngressTask|TestAggregator|TestConnectionMemory' -count 1
go test ./control/ -run 'TestUdp' -race -count 1
```
- 判据：全绿；`TestUdpIngressTaskPoolReuse` 0 allocs（防回归）

## 已知陷阱
- WSL2 的 33% NAT 丢包是 veth/环境共模——真实内核基线**重新记录**，不与 WSL2 值对比
- sender 饱和速率漂移（WSL2 8.5-17 Gbps）——真实内核同样可能存在，A/B 必须交替多轮取中位数
- pprof 短负载样本空（WSL2 教训）——负载 ≥12s，profile ≥6s

## 实测结果（已完成，2026-08-15 labs.lan）

### 微基准（outbound，-count 5 中位数）
| 基准 | 每 op | 每包成本 |
|---|---|---|
| 单包 write | 3.6μs | 3.6μs |
| 批 8 sendmmsg | 30.0μs | 3.75μs |
| 批 32 sendmmsg | 117.7μs | 3.68μs |

→ **线性**：sendmmsg 内核路径 = N×单包路径（每包内核处理 ~3.4μs 主导，syscall 边界 ~0.5μs
可忽略）——批写在此环境**无收益**（此机为真实物理 CPU 3.88GHz，非 CPU 限制所致；
loopback 发送+接收双向成本）。

### socks 路径 e2e（netns sender 8 流饱和 → dae → socks5 count-only proxy）
| 指标 | BASE（e628af76） | HEAD（批写+优化） |
|---|---|---|
| sender | 292K pps | 304K pps |
| proxy 收到 | ~180-200K（15-17K pps） | ~200K（17K pps） |
| 处理率 | ~5.1% | ~5.6% |
| Syscall6（pprof） | 61.5% | 60.9% |

→ **BASE ≈ HEAD**：批写无收益也无害（同步 flush 无阻塞恶化证据）。
批读 proxy（recvmmsg 64 批）对照确认 proxy 非瓶颈（dae 实际只转出 ~200K）。
dae CPU ~1.4 核处理全部输入（每包 ~4.6μs = 写 3.6μs + 处理 1μs）→ **用户态 UDP 转发上限
≈ 200-300K pps（此环境）**。

### 关键结论
1. **每包 UDP 处理成本（内核读+写+协议栈）是硬瓶颈**（真实内核 3.6-4.6μs，WSL2 11μs——
   方向一致，WSL2 是放大版）
2. **sendmmsg 批写无法降低每包内核成本**（内核路径不合并）——两个环境均无收益；
   在 syscall 边界占比高的环境（高性能主机、非 loopback）理论上仍可能有益，**保留代码**
   （测试/race 全绿、无负面），文档标注实测无收益
3. **dae 用户态 UDP 转发上限由每包成本 × CPU 决定**——进一步优化方向：
   ① 降低每包成本（读侧批宽已 32；处理链已优化——剩余为内核成本，不可压缩）
   ② 多核并行转发（4-socket 读 + 并行处理链——读非瓶颈，处理链并行化才是）
   ③ 接受上限（~300K pps/4 核）——真实部署通常不会单机饱和这么多 UDP 流
4. 分配优化（owned task/scratch/String 复用）在真实内核同样有效（alloc 回归测试全绿）
- 结果必须写回 `docs/research/`（防止 r 系列无记录教训重演）
