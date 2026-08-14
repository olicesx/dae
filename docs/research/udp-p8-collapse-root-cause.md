# UDP P8 坍塌根因实验记录（2026-08-15，WSL2）

> 结论先行：honk P8（8 流饱和 UDP）坍塌的根因**不是 ingress rcvbuf**，也不是单 socket
> 收包，而是**出站 UDP 写路径每包一次 syscall**（pprof：Syscall6 40.9% flat，其中写 syscall
> ~31%、读 recvmmsg ~12%）。`SetReadBuffer(8MiB)` 提交（070201f7）实测无效，已 revert。
> 另发现：`ab_bench` 的 T2 UDP e2e（fallback direct）**测的是 NAT 直通路径，dae 用户态
> 完全不参与**——此前的 A/B 结论对用户态 UDP 路径无效，需按本文档修正。

## 1. 实验链（全部 WSL2 kernel 6.18.33.2，netns+veth 拓扑）

### Step 1：rcvbuf 假设筛选（sysctl 全局 8MiB，test-udp.dae fallback direct）
| 指标 | baseline（rmem 208KB） | rmem 8MiB |
|---|---|---|
| SUM receiver | 11.8 Gbps，**31% 丢** | 15.5 Gbps，**0.099% 丢** |

→ 看似证实"rcvbuf 是瓶颈"。**但这是假象**：见 Step 2。

### Step 2：路径诊断（杀 dae 对照 + ss + TC hook）
- `test-udp.dae`（`fallback: direct`）→ eBPF 数据面直接放行（TC_ACT_OK），**不经 dae 用户态**
- 证据：杀 dae 后丢包 33%（dae 运行时 32%，几乎无差异）；dae 的 12345 listener 在 dae netns
  （host `ss` 不可见，`anyfrom_pool.go:459` `GetDaeNetns().WithRequired`）；TC hook 已挂
  （`dae_lan_ingress_l2`）；无 TPROXY iptables 规则（纯 eBPF 劫持）
- Step 1 的 8MiB 改善实际作用于 **iperf3 server 的 rcvbuf**（NAT 路径终点）——与 dae 无关
- **方法论教训：`ab_bench/02_e2e.sh` 的 UDP T2（fallback direct）全程测 NAT 直通**，
  "dae 用户态无回退"结论无效；真实用户态路径必须用非 direct 出站（socks5 等）

### Step 3：socks 路径（真实 honk 场景，test-socks-hp.dae：dport 5201 → socks5-grp）
拓扑：netns sender → dae tproxy → socks5 (127.0.0.1:1080) → receiver (127.0.0.1:5201)

| 配置 | 丢包 |
|---|---|
| BASE（e628af76，无改动） | 96.3% |
| FIX（070201f7 代码 8MiB） | 95.3% |
| FIX + 全局 rmem 8MiB | 91.9% |

→ rcvbuf 放大仅 ~3-4pt（来自 receiver 端），**dae ingress rcvbuf 不是瓶颈**。
→ dae CPU ~1922 ticks/sample（多核忙，HZ=250 估算 ~7.7 核）。

### Step 4：三段分解（proxy `-count-only`，只测 dae→proxy 段）
- sender：10,664,029 包 / 888,669 pps / 8.53 Gbps
- proxy 收到：440,000 包（~36K pps）→ **dae 用户态只处理输入 4.1%，丢包 95.9% 全在 dae 内部**

### Step 5：pprof（6s，Total 21.43s @ 357% ≈ 3.6 核）
```
Syscall6          40.92% flat  ← 写 syscall 29.96%（directPacketConn.Write→net.Conn.Write）
                                  + 读 recvmmsg 12.32%（udpIngressBatchReader.ReadBatch）
socks5.PktConn.WriteTo  cum 38.78%（封装 + 写）
UdpEndpoint.WriteTo     cum 44.24%（每包原子/TTL/时间戳 + 写）
UdpTaskQueue.convoy     cum 72.61%（worker 汇聚点）
handlePktOwned          cum 55.62%
```
→ **每包一次 UDP 写 syscall 是最大单项热点**（10.66M 包 = 10.66M 次写 syscall；
WSL2 hv 使单次 syscall ~2-3μs，放大效应明显，但真实内核上同样存在且可优化）。

## 2. 结论与决策

1. **070201f7（SetReadBuffer 8MiB）已 revert（23bc22c9）**：两个场景均无实测收益
   （NAT 路径不经 dae；socks 路径 8MiB 无效）。防御性设置不构成提交理由。
2. **下一步优化方向（按 pprof 证据排序）**：
   a. **出站 UDP 批写（sendmmsg/SendMsgs）**：socks5/direct 出站路径每包一次 write →
      批量 syscall /32（dae 已用 `x/net` 的 `RecvMsgs` 批读，出站批写对称可行）——预估
      写 CPU 31% → ~1-2%。涉及 outbound fork（directPacketConn）+ 调用链改造。
   b. 读批宽调大（当前 32）——读仅 12%，收益有限，优先级低。
   c. convoy/每包原子开销（UdpEndpoint.WriteTo 的 TTL/时间戳/remember 链）——微优化，
      在 (a) 之后评估。
3. **验证方法修正**：用户态 UDP 路径的 A/B 必须用非 direct 出站（socks5 拓扑），
   `ab_bench` 需补该场景；WSL2 的 syscall 放大需在真实内核复测确认收益量级。
4. **遗留问题**：socks 路径 4.1% 处理率中，读 12% + 写 31% + 其余 57%（处理/调度/GC/锁）
   的剩余部分待进一步分析（convoy 汇聚 72.6% cum 值得单独看）。
