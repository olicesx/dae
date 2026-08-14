# UDP ingress rcvbuf 实验记录（2026-08-15）

> 结论先行：**dae ingress UDP listener 未设置 SO_RCVBUF，使用系统默认 208KB rcvbuf，
> 在 8 流饱和（iperf3 UDP P8, 10G target）下内核接收队列溢出，端到端丢包 31%。
> 将 rcvbuf 提到 8MiB 后丢包降至 0.099%，接收吞吐 11.8 → 15.5 Gbps（=发送全收）。**

## 背景

- 问题：`udp_probe/hp_test.sh` / `e2e3.sh` 场景（honk P8）中 UDP 多流饱和丢包
- 独立分析（GLM 子代理）发现：dae ingress listener（`control_plane.go:2862` `ListenPacket`）
  **无任何 SetReadBuffer 调用**（全仓库仅出站 dialer `default_network_dialer.go:93` 有），
  而探针 `reuseport_test/main.go:61-62` 特意设 8MiB 并注明 "like honk's listeners"——反证现状用默认值
- 实测确认：WSL2 kernel 6.18.33.2，`net.core.rmem_default = 212992`（208KB）

## 实验设计（Step 1：假设筛选，零代码改动）

- 环境：WSL2 Ubuntu（root），kernel 6.18.33.2-microsoft-standard-WSL2
- 拓扑：netns daelab + veth，dae HEAD（1f1cd930，`/root/daes_bench/ab/head/dae/dae`）
  tproxy（lan=daelab, tproxy_port 12345, fallback direct）
- 负载：iperf3 UDP P8，`-b 10G -l 1200 -t 12`，server 绑 host veth IP 10.99.0.1
- 变量：仅 `net.core.rmem_default/rmem_max`（208KB/4MB vs 8MiB/8MiB），sysctl 在 dae 启动前设置
- 脚本：`tmp/rcvbuf_test.sh`（WSL 侧执行）

## 结果

| 指标 | baseline（208KB） | rmem 8MiB |
|---|---|---|
| SUM sender | 24.0 GB, 17.2 Gbps, 0% 丢 | 21.7 GB, 15.5 Gbps, 0% 丢 |
| SUM receiver | 16.5 GB, 11.8 Gbps, **31% 丢**（6,761,842/21,512,550） | 21.7 GB, 15.5 Gbps, **0.099% 丢**（19,158/19,431,202） |
| 单流最差 | 51% 丢（流 17） | 0.61% 丢（流 19） |

观察：
- 丢包率 31% → 0.099%（~300x），接收吞吐 +31%
- rmem 8MiB 下发送速率微降（17.2→15.5 Gbps）是健康信号：拥塞反馈传回 sender，
  之前"多发的"正是被丢弃的部分（发送-接收差 = 丢弃量）
- 混杂因素：sysctl 全局生效，同时影响 dae ingress listener 与 iperf3 server 的 rcvbuf
  → 需 Step 2 归因（仅改 dae 代码）

## Step 2（待执行）

- 代码：`control_plane.go` `Listen()` 对 UDP packetConn `SetReadBuffer(8 << 20)`，双栈与 IPv4 fallback 分支均设置
- sysctl 恢复默认（rmem_max=4MiB，验证 root 下 SO_RCVBUF 可超 rmem_max；实际值用 `ss -m` 确认）
- 判据：丢包保持 <1% → 归因 dae listener（正确）；回升 → 需评估 iperf3 server/其他环节
- 成功后：提交到 kdae 分支，并评估是否补配置项（对齐出站 `defaultUDPReadBufferSize = 4<<20` 模式）

## 结论与后续

1. **4-socket 改造的决策依据更新**：rcvbuf 是 P8 丢包的第一瓶颈，修它可能即可达无损；
   4-socket（并行收包）解决的是单 goroutine 串行排水吞吐上限，两者正交——先修 rcvbuf 再复测，
   若单核排水仍封顶（>15.5Gbps 需求）才需要 4-socket
2. 验证留档：本轮为"改什么测什么 + 单变量隔离 + 结果留档"的实践（对应 pool 摇摆教训）
