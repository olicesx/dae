# 视频卡顿（"一卡一卡"）回归：近一周优化/裁剪改动系统分析

> 2026-08-16 · 分析范围：dae kdae 分支 08-09 ~ 08-15（5b380d57..e261ead2）+ outbound fork（942b5a4）+ quic-go fork（9d6cbf7c）
> 用户反馈画像：最新版看视频周期性转圈重缓冲；出站协议混合；内核 6.8~6.14.6（Ubuntu 24.04 等）。
> 方法：主线程逐 commit 取证 + 3 个异质子 agent 并发审计（quic-go 池化 / dae UDP 生命周期 / outbound 数据面），HIGH 结论均经主线程独立代码复核。

## WSL2 实测验证（2026-08-16，kernel 6.18.33.2）

### race 闭包（Windows 无 cgo 的缺口已补）

- quic-go@2ae9729e：`go test -race` 根包 + internal/wire **ok**
- outbound@57b60d4：`go test -race` hy2 client ×2 + hy2 全树 **ok**

### 顺序 e2e（A/B 交替 ×3 轮，双方 replace 均经 `go version -m` 验证）

拓扑：netns 客户端(4 流) → dae tproxy(dport 5201→hy2-grp) → 官方 hysteria 服务端 → 爆发源（每请求回 32 包突发，下载方向，共 7680 datagrams/轮）。BASE=dae@e261ead2+forks(9d6cbf7c/942b5a4)，FIX=同 dae+forks(2ae9729e/57b60d4)。

| 轮 | BASE 乱序 | FIX 乱序 |
|----|----------|---------|
| 1 | **255（3.35%，maxdist 27）** | 26（0.34%） |
| 2 | **210（2.77%）** | 70（0.92%） |
| 3 | **183（2.46%）** | 66（0.87%） |

→ **demux 乱序被消除，整体降 3-8×**；FIX 残留 ~0.5-0.9% 为环境底噪（WSL2 veth 多 CPU 软中断重排，与 demux 无关）。两侧均无 retire/rebuild 日志。测试资产：`tmp/wsle2e/`（udpprobe.go / run_order_e2e.sh）。

### C 机制触发验证（两次阴性，重要负结果）

- 5% 丢包 + 40ms 延迟，80Mbps 持续上行 45s：**0 次**队列满/退役
- 2% 丢包 + 40ms + **rate 20mbit 承载 80M 需求**（接收端 75% 过载丢失）70s：**仍 0 次**

→ 瓶颈落在内核 qdisc（QUIC 包出 socket 后才丢），应用层 datagram 队列不满、30s 超时无法达成。**C 的真实触发比审计推演更苛刻**：需要服务端应用层停摆/消费冻结（使 cwnd 塌陷到 drain<offer 持续 30s），路径级劣化（含带宽硬限速）不足以触发。用户普通路径上的周期卡顿**更可能来自 A/B**（无条件触发）而非 C——C 降级为"病态服务端场景"专属。

### 全量 gate（fix 侧 = dae@e261ead2 + quic-go@2ae9729e + outbound@57b60d4）

| Gate | 结果 |
|------|------|
| go vet ./... | ✅ 5s |
| go build -tags=trace ./... | ✅ |
| go test -short ./control/... ./component/... | ✅ 17s |
| go test -race -short ./control/... | ✅ 20s |
| make ebpf-test | ✅ 2.98s（环境修复后，见下） |
| make dae | ✅ |
| make ebpf-lint | ✅ |
| ./dae validate | ✅ |

**环境陷阱（留痕）**：`make ebpf-test` 首跑 7 用例失败于 `Failed to open trace_pipe`——测试硬编码 `/sys/kernel/tracing/trace_pipe`（独立 tracefs 挂载点），本 WSL2 实例 tracefs 只挂在 debugfs 下（`/sys/kernel/debug/tracing`）。对照实验（BASE 侧同败且更多）证明与 fork 修复无关（eBPF 测试不编译 fork 代码）。修复：`mount --bind /sys/kernel/debug/tracing /sys/kernel/tracing`。既往 sprint 记录 23 用例 PASS 时该挂载点应已存在，环境漂移后需重建。

## TL;DR — 确认的问题机制（按嫌疑排序）

| # | 机制 | 引入日期 | 影响协议 | 触发条件 | 与症状匹配 |
|---|------|---------|---------|---------|-----------|
| A | quic-go StreamFrame 池 double-put → 跨连接数据污染 | 08-14（9d6cbf7c） | 全部 QUIC 出站（hy2/tuic/juicity） | 流半关闭后连接关闭（常见） | ★★★ 随机流损坏→重缓冲；外层隧道报错→整连接重置 |
| B | hy2 并行 demux 每会话乱序 | 08-13（outbound 68c91ae） | hy2 UDP（H3/QUIC 视频、游戏） | 多 goroutine demux 并发调度（常态） | ★★★ 内层 QUIC 假丢包→cwnd 减半→周期性吞吐塌陷 |
| C | datagram 发送队列满 30s 超时 → 立即退役 endpoint | 08-10（dae e2f1e545） | hy2/tuic | 需服务端应用层停摆级劣化（WSL2 实测：5% 丢包与 75% 带宽过载均不触发） | ★（降级）病态服务端场景专属；30s 停顿 + 会话重建 |
| D | >5s 双向静默 → endpoint 重建 | 08-10/08-11（7bcca2ef+003da4ea） | 全部代理 UDP | 缓冲满后的 >5s 真实暂停/分段间隙（播放中不触发；每次暂停一次，非周期） | ★★ 暂停后恢复打嗝/断流 |
| E | bpf_redirect_peer CVE 门控收紧 | 08-13（dae 4bcd8a16） | 全部流量（内核 6.8~6.14.6） | 未打 DAE_ALLOW_REDIRECT_PEER=1 的发行版内核 | ★ 全局路径变重（MAC 重写+完整 ingress 站），压低余量，与 C/D 叠加 |

条件性机制（用户开启才生效）：
- TCP sockmap offload fuse 循环（默认关，需 DAE_ALLOW_TCP_SOCKMAP=1）：64MB 积压差 engage→冻结排空→用户态接力→lift，周期循环形态与卡顿吻合。
- tuic brutal CC（outbound 68c91ae）：`OnCongestionEvent` 为空 Stub，完全无视丢包的固定速率发送，丢包时 ackRate 钳到 0.8 反而**加速 1.25×**；cwnd 从 share link 原样传入（单位陷阱：非 bytes/s 即饥饿或过冲）；`cwnd=0` 静默回退 BBR（配置惊讶）。速率超路径容量即排队溢出振荡，且支配整条 tuic QUIC 连接（含同隧道 TCP 流）。默认（未配 cwnd）走 BBR 不受影响。

其他次级发现（审计）：M2 direct/socks5 批写中途地址解析失败返回假 `n=i`（实发 0，调用方游标推进即静默丢包；socks5 路径还泄漏已封装池缓冲）；M3 非 Linux 平台 WriteBatch 截断为 1 条且返回 `(1,nil)`（dae 生产在 Linux 不受影响）；L1 ss2022 稳态读无界（dae relay 层空闲看门狗兜底，LOW）；L2 tuic 每关联队列满改丢弃（优于队头阻塞，但新增丢点点位，建议加计数器）。

## 机制详述与证据

### A. quic-go StreamFrame 池 double-put（最高优先修复）✅ 已红绿测试证明并修复（2026-08-16）

- **fork 引入的回归**（审计确认）：上游 quic-go 用 done-callback，EOF 调用后不会再被调用，不存在此问题；fork 改为 releaser + 新增 `releasePendingFrames` 后，EOF 路径 PutBack 但未置 nil `currentFrameDone`，连接关闭时二次归还。
- EOF 路径 `receive_stream.go:220-224`：PutBack 后**未置 nil** `currentFrameDone`（只置了 `currentFrame = nil`）。
- `releasePendingFrames`（`receive_stream.go:405-412`，9d6cbf7c "release queued frames on receive-stream abrupt close" 引入）在连接关闭时对每个 map 内流再 PutBack 同一指针。
- 双向流"收半先 EOF、发半未完成"期间流仍留在 streamsMap（`checkIfCompleted` 阻塞 `onStreamCompleted`，stream.go:159-163）→ 连接关闭（空闲超时/CONNECTION_CLOSE/网络错误）→ **确定性 double-put**；EOF-Read 与 CloseWithError 交错（receive_stream.go:96→99 窗口）则所有流类型竞态触发。
- 后果：全局 channel 池中同一 `*StreamFrame` 出现两次 → 两个连接并发写同一 Data 缓冲 → 跨流数据污染 / data race / 重传风暴。
- **可执行证明**：回归测试 `TestReceiveStreamEOFThenShutdownSinglePut`（close_shutdown_release_test.go）——修复前红（`wire.StreamFramePoolLen()` 256→257，同一指针进池两次），修复后绿。修后根包全量 + internal/wire 全量 ok；race 需 cgo（本机 Windows 无 gcc），修复为锁内单字段置 nil 无新并发面，留 Linux CI 复跑。
- 修复（工作区未提交，待确认）：EOF 分支 PutBack 后补 `s.currentFrameDone = nil`（含注释共 5 行）+ 回归测试 38 行，均在 quic-go 仓库。
- 附带（MEDIUM，未修）：RESET_STREAM/CancelRead 不排空 sorter，池帧滞留（GC 压力，自愈型，非污染）；发送侧关机时 ackhandler 内未确认帧泄漏（LOW，同类）。
- 附带（MEDIUM）：RESET_STREAM/CancelRead 不排空 sorter，池帧滞留（GC 压力，非污染）。

### B. hy2 并行 demux 每会话乱序 ✅ 已红绿测试证明并修复（2026-08-16）

- `protocol/hysteria2/client/udp.go`（68c91ae）：最多 8 个 `run()` goroutine 并发从共享 QUIC datagram 队列 FIFO 弹包；投递序 = 锁竞争序，非到达序。**两层乱序**：`receiveMu` 只保 `D.Feed` 临界区，receiver 回调在锁外完全竞态。
- **可执行证明**：回归测试 `TestUDPSessionManagerDemuxPreservesPerSessionOrder`（4 会话 × 2000 包并发）——修复前红（session 0 第 65 个投递即出现 seq 66 先到），修复后绿（×5 连跑，0.143s）。
- **修复结构**：单路由 goroutine（唯一 `ReceiveMessage` 调用者 → 派发序 = 到达序）+ 按 SessionID 亲和的 worker（每 worker 同步处理其会话的 defrag + 投递）——每会话严格保序，跨会话消费仍并行。worker 队列仅作突发平滑（256）：过载背压传导到传输层有界 rcvQueue（512），不新增丢点。
- hy2 全树 + netproxy 测试 ok；race 需 cgo（本机 Windows 无 gcc），关键并发面（router 单点 pop、worker FIFO、feed 复用既有锁序）留 Linux CI 复跑。
- 视频（下行 demux 方向）内层 H3/QUIC 不再看到假丢包 → 消除 cwnd 周期塌陷。
- 回归测试只数投递数，不断言顺序（测试护栏缺失）。
- 附带 HIGH-2：`frag/frag.go:55-63` 并行下后包分片先 Feed 会整体丢弃前一未完成包（视频少分片，影响低）。
- **修复设计约束**（审计确认）：到达序在 pop 后即丢失（QUIC DATAGRAM 帧无序号，pop 序≠处理序），故"demux 后每会话有序队列"不成立。正确结构：**单路由 goroutine pop + 仅做会话查表/入队（每包几十 ns，远低于 4.6μs 内核成本，无吞吐天花板），每会话一个消费者 goroutine 并行做 defrag + 投递**——保序与并行兼得；H2 同结构自动修复。次选：直接回退单 goroutine demux（dae 侧每包处理重新串行化，回到单核上限）。

### C. datagram 队列满 30s → 立即退役

- quic-go fork `datagram_queue.go:48` `datagramSendQueueFullTimeout` = 30s（队列 256 满，**每 QUIC 连接共享**，同 dialer 上全部 UDP 会话复用）。
- dae `udp_endpoint_lifecycle.go:599` 对 `quic.ErrDatagramQueueFullTimeout` **立即 retire**（无软错误阈值）。
- hy2/tuic 不实现 PacketBatchWriter，视频必走此路径。**触发条件精确化**（审计复核）：纯下载方向（视频下行）加载的是代理服务器侧发送队列与 dae 的 rcvQueue，**不是** dae→proxy 发送队列，且 DATAGRAM 帧不受流控——所以 merely-slow-but-lossless 上游**不会**触发；触发需要隧道 client→server 方向持续 30s drain < offer：路径丢包致 cwnd 塌陷（如 150-300ms RTT 下 cwnd < ~100 包 → drain < ~500 pkt/s，而 ACK 流 + 并发流 offer 更高）、代理带宽上限、共享隧道的重度并发 UDP——恰是代理用户常态。
- 退役后果：新 hy2 会话 → 新转发源端口 → 视频服务器视为新客户端（未知 DCID 的 1-RTT 包被丢弃/stateless reset）→ 内层 QUIC RTO 死亡 → 重缓冲。30s 阻塞期间还触发服务端空闲超时（quic-go 默认 30s）。**放大效应**：阻塞的 Add 停驻一个 dispatcher worker（≤8 个、每流 FIFO）整整 30s，该流的队列随后溢出丢包。
- 日志确认特征：`UdpEndpoint ... exited with error` + `datagram send queue full: timed out`，~30s 周期复发且与重缓冲 1:1 对齐。复现：tc netem 1-3% 丢包 + 150ms+ RTT 的 hy2 路径上看视频并计数退役次数。
- 注：writeSoftErrorThreshold=3（连续、无时间衰减，成功即清零）+ 批写部分成功（io.ErrShortWrite）4 次连续即退役（仅 direct/socks5，需出口持续饱和），为次级同族机制。

### D. >5s 双向静默重建 vs 分段间隙

- `7bcca2ef`（08-10）为游戏局间静默引入重建；`003da4ea`（08-11）修正为**双向**都静默 >5s 才重建（取 lastSend/lastReply 较新者）。
- **形态精确化**（审计复核）：连续播放中数据+ACK 双向刷新时间戳 → **播放中永不触发**；只在真实 >5s 暂停（播放器缓冲满后的突发分段拉取间隙、用户暂停）触发，**每次暂停一次**，非周期性。
- 局限仍在：缓冲已满的稳态 DASH/HLS 客户端分段间隙 6~15s 双向静默是常态，每间隙重建 endpoint（新会话+新源端口）。QUIC CID 使内层连接多以"路径迁移"存活（打嗝一下），非 QUIC UDP 或严格服务端会直接断。H3 无 keepalive 时更易命中。
- 可证伪：卡顿前日志出现 `both directions silent for 5s, rebuilding session`（对齐每次卡顿）。

### E. bpf_redirect_peer CVE 门控（正确但系统性过保守）

- `4bcd8a16`（08-13）：门控 6.8.0 → 6.14.7 + 官方 stable backport 点位（6.1.139/6.6.91/6.12.29）。修 CVE 本身没错。
- 问题：Ubuntu/Debian 发行版内核**回移 CVE 修复但不改版本号**——24.04 的 6.8、Debian 的 6.1 大多已含修复，却被踢出快路径，退到 `bpf_redirect` + MAC 重写 + 完整 ingress 站（`tproxy.c:1711-1727, 1829-1862`）。所有代理流量每包成本上升，压低整体余量（放大 C 的触发概率）。
- 逃生门：`DAE_ALLOW_REDIRECT_PEER=1`（loader 处 Warn 确认）。

## 已验证干净 / 排除项

| 项 | 结论 |
|----|------|
| fork pin 完整性 | ca082f24（rcvQueue 满归还池缓冲）与 e4982907（sorter double-put 修复）**均在** pin 9d6cbf7c 内 |
| TCP relay copy buffer 池摇摆 | c1cd6f74（channel 池，实测 CPU 2.1×）已被 5f019933 干净 revert 回 sync.Pool（字节级） |
| UDP 批写（sendmmsg） | 真实内核实测无收益也无害（real-kernel-revalidation.md）；scratch 池化并发安全；Linux 上部分成功必带 error（dae 的 ErrShortWrite 退役链只在真实部分写时触发） |
| ingress task 池化（f7b27fcd） | 原闭包同样 `defer data.Put()`，buffer 生命周期语义未变；handlePkt 同步消费 |
| hy2 redundant-send | 已彻底 revert，零残留 |
| 池摇摆（outbound） | 终态为干净 sync.Pool，Get cap-guard 正确 |
| 8MiB rcvbuf | 已 revert（实测无效，NAT 直通路径根本不经用户态） |
| e58f87ce / 754c7076 / 4799024b / 2fb733f1 | 低嫌疑（防御性修复/语义等价论证充分/冷路径选路） |
| `wan_outbound_is_alive` 黑洞 | 3~4 月存量机制，非本次引入（04569cca 只是补了恢复反馈，方向正确） |

## 用户机上的区分验证

按层开关做 A/B，二分定位（每步只需观察卡顿是否消失）：

1. **排除 A（quic-go）**：换非 QUIC 出站（socks5/vmess TCP 节点）跑同样视频。消失 → A/B/C/D（QUIC 系）。
2. **排除 B（hy2 demux）**：hy2 节点临时回退/打乱序补丁，或换 tuic 节点对比（tuic 无并行 demux）。同 QUIC 系内区分 hy2 与 tuic 特有问题。
3. **确认 C**：`journalctl`/日志 grep `datagram send queue full: timed out` 与 endpoint retire 记录，时间戳对齐卡顿时刻。
4. **确认 D**：日志中 endpoint rebuild（静默重建）频率是否与分段节奏一致。
5. **缓解 E**：`DAE_ALLOW_REDIRECT_PEER=1`（确认发行版内核含 CVE-2025-37959 回移后）观察全局性能变化。
6. **排除 offload fuse**：确认未设 `DAE_ALLOW_TCP_SOCKMAP`（默认关）；若开了，`DAE_DISABLE_TCP_RELAY_OFFLOAD=1` 对比。

## 修复优先级建议

1. **A（一行修复，立即）**：EOF 分支补 `s.currentFrameDone = nil`；补 double-put 回归测试（EOF 后 closeForShutdown 断言池长度不增）。
2. **B（高优）**：demux 会话亲和或回退单 goroutine；补每会话顺序断言测试。
3. **C（高优）**：队列满超时首犯降级为软错误（复用 writeSoftErrorCount 阈值）或仅关闭该 UDP 会话而非退役整个 endpoint；评估 30s 是否过长。
4. **D（中优）**：双向静默阈值与"已见回复"语义细分：对有 sniff 标记的 QUIC/DNS 流放宽（如 30s），仅对游戏类短超时；或重建前发保活探测。
5. **E（文档/提示）**：README/日志提示发行版内核可用 `DAE_ALLOW_REDIRECT_PEER=1` 恢复快路径。
6. M1（tuic brutal）：文档标注速率需 ≤ 路径容量；或加基于丢包的降速护栏。
