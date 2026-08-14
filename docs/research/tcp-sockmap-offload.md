# TCP sockmap 中继卸载：研究取证与重新启用设计（kdae）

> 日期：2026-08-14 · 决策：重新启用 TCP relay 内核卸载，但采用修正后的数据面机制（sk_skb stream_verdict + egress redirect），
> 并镜像 kdae 现有 CVE 版本门控模式（`RedirectPeerSafeVersion` 同款）。

## 一、结论

1. kdae 当前 `fast_sock`/`tproxy_sockops`/`tproxy_sk_msg_redir` 是**被上游 dae PR #912 彻底移除后遗留的禁用 stub**（map 容量压到 1、程序返回 SK_PASS/BPF_OK）。
2. 上游移除的两个真实原因：**内核 panic** 与 **sk_msg 数据面机制错误**。两者都有权威证据，且都有规避方案。
3. 重新启用方案：**纯用户态定向插桩 + sk_skb（RX 路径）egress 重定向**，不用 root-cgroup sockops、不用 sk_msg，按 CVE-2025-38165 修复版本矩阵门控，失败静默回退 splice 快路径。

## 二、上游历史证据链

| 提交/PR | 内容 |
|---|---|
| [dae#481](https://github.com/daeuniverse/dae/pull/481)（b6c3f69b, 2024-03） | 引入 sockmap 快重定向：root cgroup `sockops` 插桩 + `SEC("sk_msg/fast_redirect")` + `fast_sock` SOCKHASH |
| [dae#518](https://github.com/daeuniverse/dae/pull/518)（ec7cf06d） | 默认关闭。"A kernel issue (confirmed by community) breaks TCP clients (e.g. glider) who use splice syscall when enabling bpf sockmap redirect"，附复现器 [jschwinger233/bpf_msg_redirect_bug_reproducer](https://github.com/jschwinger233/bpf_msg_redirect_bug_reproducer)。维护者评论："**预计在 6.12+ 的内核之后可以重新开启这种模式，达到 wan 代理的性能极限。tcp early demux 也一并解决了。**" |
| [dae#912](https://github.com/daeuniverse/dae/pull/912)（12b26492, 2026-04, v1.1.0） | **彻底移除**。理由：①#481→#518 已关闭 ②维护者与社区发现更多 sockmap bug ③6.12.62 OpenWrt 用户报加载失败 `local_tcp_sockops: load program: invalid argument: program of this type cannot use helper bpf_get_current_task` ④引用 LWN [Buggiest commits 2025](https://lwn.net/Articles/1038360/) ⑤维护者结论 "I don't believe sockmap can be production-ready in a handful of years"。 |
| kdae 8d3bcda8（2026-03, AI 合著） | 跟随禁用：sk_msg 返回 SK_PASS、sockops 返回 BPF_OK、`fast_sock` 容量压到 1、Go 实现删除。**未附 panic 证据链接**。 |

> #912 的 6.12.62 加载失败根因是 sockops 程序用了 `bpf_get_current_task`（该 helper 对 sock_ops 受限）。
> **本设计不挂载任何 sockops 程序**，该失败模式被结构性消除。

## 三、panic 根因与内核修复矩阵（权威证据）

**CVE-2025-38165**（[linux-cve-announce 2025-07-03](https://lists.openwall.net/linux-cve-announce/2025/07/03/72)）：`bpf, sockmap: Fix panic when calling skb_linearize`。

- panic 栈：`sk_psock_backlog → sk_psock_skb_ingress_enqueue → skb_linearize → BUG_ON(skb_shared(skb))`（`kernel BUG at net/core/skbuff.c`）。
- 触发条件：**单条消息超过 MAX_MSG_FRAGS（约 100KB）经 sockmap ingress 重定向**。dae 中继转发大 POST/大文件极可能触发。
- 影响/修复版本矩阵：

| 系列 | 引入 | 修复 |
|---|---|---|
| mainline | — | 6.15.3 / 6.16-rc1 |
| 6.12.y | 6.6 | **6.12.34** |
| 6.6.y | 6.6 | **6.6.94** |
| 6.1.y | 6.1.54 | **6.1.142** |

**同批与后续修复**（bpf-next）：
- 2025-04-07 [bpf, sockmap: Fix data loss and panic issues 0/4](https://lists.openwall.net/linux-kernel/2025/04/07/1273)：EAGAIN 重试方向错误丢数据、部分发送 offset 未记录致重复发送、上述 panic、`ingress_skb` 内存不受 socket/memcg 限制（当时未修）。
- 2025-05 `bpf, sockmap: Fix concurrency issues between memory charge and uncharge`；2025-06 `bpf, sockmap: Fix psock incorrectly pointing to sk`。
- 2025-07 `[PATCH bpf-next v3] sockmap: Fix reading with splice(2)`（#518 splice bug 的修复线）；2026-03 `bpf/sockmap: add splice support for tcp_bpf`。
- 历史 CVE：CVE-2022-49205（double uncharge，4.20 引入）、CVE-2023-52523（egress 重定向拒绝非 TCP）。

**现代内核性能证据**：
- LSF/MM/BPF 2025 topic（Cong Wang）：skmsg 重定向吞吐较 vanilla TCP_BPF **+5%~160%**（随消息大小），~2% 延迟代价。
- 2025-04 `tcp_bpf: message corking` 补丁实测 +3.13%~160.92%（[LWN 1013362](https://lwn.net/Articles/1013362/)）。
- 反向限定：[LWN "Two sessions on faster networking"](https://lwn.net/Articles/1033063/)——短消息场景 BPF 重定向可能慢于完整 TCP 栈。
- 行业采用：Envoy *Sockmap socket interface*（同主机加速，kernel ≥4.18）、Cilium socket LB、Cloudflare [SOCKMAP 博客 2019](https://blog.cloudflare.com/sockmap-tcp-splicing-of-the-future/)（4.14 时代负例，已过时）、netdev 0x19 sockmap 教程（Fastabend）。

## 四、数据面语义修正（本研究核心发现）

**原实现（#481 与 fork 版 7c61739c）只挂 `sk_msg`（sendmsg/TX 路径）+ `BPF_F_INGRESS`**：

- sk_msg verdict 只在 socket **被写入**时运行；`BPF_F_INGRESS` 把数据投递进**对端收队列**（如同对端"收到"）。
- dae 中继拓扑是 tproxy accept socket（L）↔ dial 出站 socket（R），目标是**远端主机**：数据必须由 R 发到线上。
- sk_msg+INGRESS 只会把写操作变成"投递进对端收队列"，**不产生任何线缆字节**；L 收到的客户端数据也无人搬运（卸载后 Go 不再读写）。→ 该数据面根本无法中继远程流量。这是被禁用的深层原因之一（与 panic 并列）。

**正确机制（内核 selftests `test_sockmap` 语义）**：RX 路径 + **egress** 重定向——

- `SEC("sk_skb")` stream_verdict 程序在 socket **收到数据**时运行；
- `bpf_sk_redirect_hash(skb, &fast_sock, &peer_key, 0)`（不带 `BPF_F_INGRESS`）→ `sk_psock_skb_redirect → skb_send_sock`：**由对端 socket 把数据发到线上**；
- 两个方向各一份（L 收→R 发；R 收→L 发），即完整的双向内核 splice。

**查表语义（内核源码 v6.18 `net/core/skmsg.c`）**：`bpf_sk_redirect_hash`/`bpf_msg_redirect_hash` 查表 miss 返回 SK_DROP → **数据被静默丢弃**。程序必须先行 `bpf_map_lookup_elem` 判空，miss 返回 SK_PASS。

**egress-only 的附加收益**：CVE-2025-38165 的 panic 路径（`sk_psock_skb_ingress_enqueue`）只在 ingress 重定向时触发；egress-only 数据面不经过该路径，结构性规避。splice 破坏 bug（#518）也不再可触发（插桩范围只有中继两端的 socket，且卸载期间 dae 不对其 splice）。

## 五、重新启用设计 v2

### eBPF 侧（control/kern/tproxy.c）
1. `fast_sock` SOCKHASH 容量恢复：`MAX_TCP_OFFLOAD_NUM = 16384` 会话 × 2 条目。
2. 删除 `tproxy_sockops`（root cgroup 全机插桩：6.12.62 加载失败源 + glider splice 破坏源 + 无关 socket 污染）与 `tproxy_sk_msg_redir`（机制错误 + miss=drop）。
3. 新增 `SEC("sk_skb/tcp_offload_redirect")`：
   - 由 `msg`/`skb` 构造对端 4-tuple（key 约定与 Go 侧一致：sip=remote、dip=local、sport=remote_port、dport=local_port）；
   - `bpf_map_lookup_elem(&fast_sock, &peer_key)` 判空，miss → `SK_PASS`；
   - hit → `bpf_sk_redirect_hash(skb, &fast_sock, &peer_key, 0)`（egress）。
4. attach：`link.RawAttachProgram(AttachSkSKBStreamVerdict)` 挂到 `fast_sock`。

### Go 侧（control/tcp_offload_linux.go，移植自 7c61739c 并修正）
- `tryOffloadTCPRelay(ctx, left, right, recordL, recordR) (offloaded bool, reason string, err error)`：
  1. 门控：`tcpSockmapOffloadReady`（setup 阶段 env + CVE 矩阵 + attach 成功）+ `FastSock` map 可用；
  2. 前缀冲刷（用户态缓冲 + **内核收队列排空** `TIOCINQ` 读尽转发，带流量记账）——客户端早期数据/服务端先行问候都覆盖；
  3. 两端 unwrap 到 `*net.TCPConn` + 排空后 `TIOCINQ == 0`；
  4. 注册：`fast_sock[reversed(left)] = rightFD`、`fast_sock[reversed(right)] = leftFD`；
  5. 会话运行：epoll 监听两端 `EPOLLRDHUP|HUP|ERR|EPOLLIN`；半关闭 10s（`relayHalfCloseTimeout`）；ctx 取消即双端 close；空闲 watchdog：30s 轮询两端 `tcp_info`，5min（`relayIdleTimeout`）无进展 → close（与 `relayCore` 语义对齐）；**积压保险丝（backlog fuse）**：每 1s 采样流入（tcp_info 字节差）与流出（kprobe 记账），差值超 64MB → 写 `tcp_offload_pause` 令 verdict 改走 SK_PASS → 用户态接力转发（EPOLLIN 路径），待差值归零后解除 pause 恢复内核卸载（见第九节）；
  6. 结束时用 `tcp_info` 字节差（bytes_received）一次性记账（下载 = R 收，上传 = L 收）；
  7. 注销两端 key。
- 任何注册前失败 → `offloaded=false` 静默回退 splice/loop 快路径；注册后错误 → 关闭双端（与 relay 失败语义一致）。
- 调用点：`handleTCP` 中 `adoptTCPFlow` 之后、`relayEstablishedTCPFlow` 之前（同 7c61739c 位置）。

### 版本门控（镜像 kdae `RedirectPeerSafeVersion` 模式）
```go
TcpSockmapPanicSafeVersion = internal.Version{6, 15, 3}  // CVE-2025-38165 mainline
TcpSockmapPanicFixedStable = []internal.Version{
    {6, 1, 142}, {6, 6, 94}, {6, 12, 34},   // 官方 stable backport
}
// DAE_ALLOW_TCP_SOCKMAP=1  显式开启（默认关闭！）
// DAE_DISABLE_TCP_RELAY_OFFLOAD=1  强制关闭（兼容保留）
```
- **默认关闭、显式开启**：CVE 修复矩阵之上的内核也不自动开。原因见下节"无界积压"——psock ingress_skb 无界队列问题（bpf-next 2025-04 series issue #4）**至今未修**，上游 #912 的移除决策对这一点依然成立。开启需同时满足：env=1 + 内核过 CVE 矩阵（矩阵未过则 warn 后仍开启——显式知情选择，镜像 redirect_peer 模式）。
- 用户态兜底：offload 会话的保险丝见第九节。`Notsent_bytes` 护栏已由 pause 保险丝取代：**该护栏只能约束 socket 发送缓冲区一侧**，而实测确认堆积发生在 psock 的 EAGAIN 重试队列（不经过 socket 缓冲、不计内存），真正的封顶手段是 pause 保险丝 + 默认关闭 + 显式开启。

## 六、实测结果（2026-08-14，WSL2 kernel 6.18.33 + 本地 socks5 桩）

e2e 拓扑：netns 客户端 → dae（lan=dae-lab, wan=eth2）→ 本地 socks5 CONNECT 桩 → 同机 iperf3 服务端。

| 场景 | offload OFF（用户态 relay） | offload ON（sk_skb 卸载） |
|---|---|---|
| TCP P1 默认写 | 1.06 Gbps（405 重传） | **12.3 Gbps（0 重传）** |
| TCP P1 256KB 大包（原 panic 触发类） | 1.07 Gbps | **17.5 Gbps（0 重传）** |
| 内核健康 | clean | **clean（无 BUG/Oops/panic）** |
| fd 泄漏 | 无 | 无 |

- 数据面提升 **~12-17×**（发送方向；接收方向受测试桩用户态 io.Copy 上限 ~1 Gbps 压制）。
- **实证确认无界积压问题，并修正堆积机制**：限速探针 1G 完美无损；2G+ 时发送端不减速、接收端被压平，4.1GB 量级内存无界增长。kprobe 差分记账（fuse_probe 原型）定位：egress-only 重定向**不经过** `sk_psock_skb_ingress_enqueue`（该挂点计数恒 0，CVE-2025-38165 panic 路径结构性规避）；堆积发生在 `sk_psock_handle_skb` 的 **EAGAIN 重试路径**——`!sock_writeable(target)` → 直接 `skb_queue_tail(&psock->ingress_skb)` + `schedule_delayed_work`，绕过 enqueue 函数、不计 socket/memcg 内存（bpf-next 2025-04 series issue #4 实质）。`sk_psock_skb_redirect` 与 `skb_send_sock` 两个挂点的字节差即实时积压（实测 400MB/s 量级、1s 粒度可见）。
- **关键内核语义（决定保险丝设计）**：SOCKHASH Delete 触发 `sk_psock_drop`——**删 key 是破坏性操作**（拆 psock、丢弃重试队列、socket 报 EPOLLERR/RDHUP，实测丢 57% 在途数据）。因此"摘除降级"必须用独立 pause map 做 verdict 层开关，不能删 fast_sock key。
- e2e 期间踩坑（供复现）：①WSL2 `ip route get 本机IP` 走 table 128 经 eth2 → 宿主自连流量被 wan_egress 劫持 → 代理递归风暴；pname 规则直连可破。②verifier 拒绝裸 `bpf_map_lookup_elem`（sock 引用泄漏）→ 必须 `bpf_sk_release`。③`bpf_trace_printk` 在 sk_skb 程序被 verifier 拒绝（字符串区间）→ 调试用 `bpf_printk`+`__DEBUG`。④offload 会话半关闭时桩不会自动关闭 → half-close 10s 窗口内 fd 正常持有（12s 后回落基线，非泄漏）。

## 七、拒绝的替代方案（留痕）

| 方案 | 拒绝理由 |
|---|---|
| 原样恢复 #481/#7c61739c（sk_msg+INGRESS） | 数据面机制错误（第四节），远程流量无法中继 |
| root-cgroup sockops 插桩 | 6.12.62 加载失败 + 第三方 splice 破坏 + 全机污染（#912 实证） |
| **摘除降级 = Delete fast_sock key** | **破坏性**：Delete 触发 `sk_psock_drop`（拆 psock + 丢弃重试队列 + EPOLLERR），实测在途数据丢 57% 且连接 RST。正确开关是 pause map（verdict 层 SK_PASS，不碰 SOCKHASH） |
| **verdict 内逐包预判（读 target sock 写缓冲）** | `struct bpf_sock` 字段白名单无 `sk_wmem_alloc`/`sk_sndbuf`；redirect helper 的 EAGAIN 判定不回流 verdict——数据面拿不到"目标不可写"信号 |
| **TC/XDP 纯数据面 seq 平移直通（跨连接）** | 两条独立 TCP 连接的 MSS/TSOPT/SACK 语义不匹配需数据面重分段重写，拥塞控制整体失效；等于在 eBPF 里重写半个 TCP 栈，收益上限与 sockmap 同量级。sockmap 本身（利用对端 socket 栈）就是 TCP Splicing 思想的内核落地（Maltz 1999 → Fastabend sockmap 4.14） |
| TCP NFQUEUE 持包全内核（首包不进球、ACCEPT 让内核完成握手） | 握手死锁：SYN 被持 → 无 SYN-ACK → 客户端永不发 ClientHello → 拿不到 SNI 无法决策；破法（用户态 syncookie 握手代理 + RST 重连）代价为首连 +1 RTT 且客户端可见 ECONNRESET，无生产先例 |
| UDP NFQUEUE 持首包 direct ACCEPT | 可行（honk 已验证、kube-network-policies 同模式）但收益仅每流首包，kdae 的 TC conn_state 已让后续包走内核直通；留作后续触发条件 |
| SNI 学习直连缓存（同域后续连接 TC 卸载） | 可行（SNIpR 先例 + dae DnsCache 同构），复用型负载才有收益；留作后续 |

## 九、积压保险丝（backlog fuse）设计与实测

### 设计

无界积压的根因是 egress 重定向的 EAGAIN 重试队列不计内存。用户态封顶手段（Notsent_bytes、cgroup）均无效（实测已证），唯一可行路径是 **pause 开关 + 用户态接力**：

1. **记账**：kprobe 挂 `skb_send_sock`（流出）+ 会话 tcp_info 字节差（流入），per-tuples 差值 = 实时积压。挂点签名实测验证（`sk_psock_skb_redirect` PARM2=skb、`skb_send_sock` PARM4=len）。
2. **触发**：差值超阈值（`tcpOffloadMaxPeerBacklog` 64MB）→ Go 侧向 `tcp_offload_pause`（LRU_HASH，key=tuples）写 key。
3. **降级**：verdict 程序命中 pause key → SK_PASS（数据留在有界收队列，TCP 流控冻结 sender）；已重定向 skb 继续由内核排空（psock 未拆除、零丢弃）。
4. **drain-wait**：会话首次 SK_PASS 进入一次性 drain 等待（欠账排空时间），期间 EPOLLIN 摘除防忙轮询；到期后用户态接力转发（EPOLLIN 路径，读/写 deadline 防卡死）。
5. **恢复**：差值归零 → 删除 pause key → verdict 恢复重定向（re-offload 免费获得，无需重新注册）。

### 实测（WSL2 6.18.33，裸 TCP 4GB @ 2Gbps，t=12s 触发）

| 阶段 | 观察 |
|---|---|
| 触发前 | 2Gbps 内核卸载满速 |
| drain-wait 期 | sender 被 TCP 流控压停（窗口残留 ~26MB），欠账全额排空 |
| 恢复期 | 用户态接力 ~960Mbps 平滑续传 |
| 终态 | **CLI_SENT 4GB == SRV_RECEIVED 4GB：零丢失、零切断** |

### 产品化实测（自动触发，无外部工具）

- 记账：fentry 挂 `skb_send_sock`（BPF trampoline 免 kprobe trap 开销），PERCPU_HASH 免全局锁，按 reversed four-tuple 记流出；流入用 tcp_info 字节差；用户态接力字节记会话内计数（不写 map，避免与内核侧竞态）。
- 闭环：backlog > 64MB → engage（写 pause + drain-wait 冻结）→ 差值归零 + RX 排空（`drainResidual`）→ lift（删 pause + re-offload）。持续饱和流下 lift 不触发是正确语义（接力速率 = 对端消费速率，无实际损失）；突发后回落的流量 lift 后自动恢复内核卸载。
- 实测：4GB 全量无损；engage/lift 日志确认完整闭环；严格 A/B 交替（`DAE_FUSE_ACCOUNT=0/1`）证明 fentry accounting **零性能开销**（default 11.9 vs 11.9 Gbps）。

### 调试中修复的实现 bug（留痕）

1. `firstClose` 被任意 epoll 事件（含 EPOLLIN）置位 → half-close 10s 误启动 → 误杀连接；修正：仅 `closedMask != 0` 时置位。
2. drain 到期 re-ADD 后 RX 残留数据立即触发 EPOLLIN → 再次进入 drain → 每 10s 循环、转发永不启动；修正：`fuseDrainDone` 一次性守卫。
3. `relayPassData` 的 Read 无 deadline 会卡死会话循环；修正：读/写均设 deadline，超时视为暂空。

### 原型资产

- `fuse_probe/`（workspace）：kprobe 差分记账探针（fuse_kprobe.bpf.c + main.go）、pause 触发工具（pause.go，pidfd_getfd 跨进程操作 map）、裸 TCP 限速收发器（nctest.go）、实验 harness（run_fuse.sh / fuse_detach.sh / fdprobe.sh）。

## 八、权威文献索引
- dae#481/#518/#912 及 [bpf_msg_redirect_bug_reproducer](https://github.com/jschwinger233/bpf_msg_redirect_bug_reproducer)
- CVE-2025-38165 公告（linux-cve-announce）；CVE-2022-49205；CVE-2023-52523
- bpf-next 2025 sockmap 修复系列（Jiayuan Chen 0/4 与后续）
- 内核源码 v6.18 `net/core/skmsg.c`（verdict/redirect 语义）、`kernel/bpf/sockmap.c`（helper）
- LSF/MM/BPF 2025 skmsg 性能 topic；LWN 1013362 / 1033063 / 1038360
- Envoy *Sockmap socket interface* 官方文档；Cilium socket LB；Cloudflare SOCKMAP 2019；netdev 0x19 教程
- Aron et al., *An Evaluation of TCP Splice Benefits in Web Proxy Servers*, WWW 2002（splice 基线：CPU −10~43%）
- Cohen & Rangarajan, *TCP Splice for application layer proxy performance*, IBM TR RC 21139, 1998
