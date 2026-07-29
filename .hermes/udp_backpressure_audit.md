# kdae UDP 背压机制审计报告

## 审计范围

审计 UDP 包从 BPF → 用户态 convoy 执行完整数据路径的每级背压，验证在**不开 udp-ordered-dispatcher / udp-reply-dispatcher** 的情况下，convoy 路径的 overflow slice 是否有足够的上游背压保护。

---

## 1. BPF 内核侧 → 用户态：数据路径

### 关键发现：BPF ringbuf 不承载 UDP 数据包

`control/kern/tproxy.c` 中定义 `event_ringbuf`（BPF_MAP_TYPE_RINGBUF，256KB），但它**仅用于 dae 事件/连接跟踪信息**（`send_dae_event` 写入 PID、pname、outbound、tuples 等），不承载 UDP 包数据。

**实际 UDP 数据路径**：eBPF TC hook → TProxy 重定向 → tproxy_listener 用户态 UDP socket。UDP 包通过 `ReadMsgUDPAddrPort` / `ipv4.ReadBatch` 系统调用进入用户态，不经过 ringbuf。

**SO_RCVBUF**：UDP ingress socket 未显式设置 SO_RCVBUF（`TproxyControl` 只设了 IP_TRANSPARENT / IPV6_TRANSPARENT、SO_REUSEADDR、SO_REUSEPORT、IP_RECVORIGDSTADDR）。使用系统默认值（Linux 默认 `net.core.rmem_default` ≈ 212KB），约 140 个 MTU 1500 包。这是最底层背压——内核 socket buffer 满后，内核直接丢弃 UDP 包。

---

## 2. 用户态 read loop → processPacket（control_plane.go:3836-4132）

### batch read 路径（IPv4 listener，line 4082-4106）
```
batchReader.ReadBatch()         // 系统调用，一次最多读 8 个包
  → for i := range n { Take(i) → processPacket(...) }
```

### single read 路径（dual-stack 或 fallback，line 4109-4132）
```
udpConn.ReadMsgUDPAddrPort()    // 系统调用
  → processPacket(pktBuf, src, oob)
```

### processPacket 中的 tryAcquire（line 3850）

```
processPacket:
  [已经 read 完毕，pktBuf 持有数据]
  → tryAcquire()                 ← LINE 3850：read() 之后
  → task := func() {             ← LINE 3854：闭包定义
      defer release()            ← LINE 3858：闭包内的 deferred release
      ...handlePkt...
    }
  → submitOrderedUDPIngress(key, task, discardTask)  ← LINE 4067：enqueue 之前
```

**验证通过**：tryAcquire 在 `read()` 之后、`enqueue()` 之前。release 在 task 闭包的 defer 中。

### discardTask 路径（line 4059-4062）

当 `submitOrderedUDPIngress` 返回 false 时（理论上仅在 handlePkt 能走通时不会发生，因为 convoy EmitTask 的失败条件是 pool closed），执行：
```go
func() { c.udpIngressAdmission.release(); pktBuf.Put() }
```

**release 配对验证**：每个成功 tryAcquire 后，必有一条路径到达 release：
- 正常路径：task 闭包内 `defer release()`（line 3858）
- 丢弃路径：discardTask 直接调用 release（line 4060）
- 异常路径：如果 task 闭包 panic，convoy 的 recover 不调用 release → **可能泄漏 inflight 计数**（但 gate 在正常操作中不为背压所用，此泄漏仅在 shutdown/drain 时可见）

---

## 3. routingEpochIngressGate 的 acquire/release 配对

### 三次 release 路径

| 路径 | 代码位置 | 条件 |
|------|---------|------|
| task closure defer | line 3858 | 正常执行流程 |
| discardTask | line 4060 | submitOrderedUDPIngress 返回 false |
| DNS/other return in task | 散落在 task 闭包各 return 点 | 仍由 defer release() 保证 |

**结论**：所有 acquire 都有对应 release。唯一潜在问题是 task 内 panic 未覆盖（convoy 的 recover 清理 queue 但不 release gate），但这个泄漏只在 reload 时影响 `closeAndWait` 的完成性，不影响正常背压。

### gate 计数的含义

```
inflight_gate_counter = tryAcquire 成功数 - release 执行数
                     = 已 read 但 task 尚未执行完的包数
```

- **正常操作**：这个计数无上限——kernel socket buffer 读完后、tryAcquire 可以连续成功很多次（batch read 一次 8 个包 × 多轮循环），而 release 在 convoy 顺序执行时才触发。
- **closeAndWait**：等待该计数归零（加 `routingEpochIngressClosed` 标志位后，等待所有 inflight 包完成）。

**gate 不是背压机制**，它是**优雅关停的排水机制**。

---

## 4. Convoy overflow 增长条件（udp_task_pool.go）

### 数据结构

```
UdpTaskQueue:
  ch:            chan UdpTask     // 容量 128 (UdpTaskQueueLength)
  overflow:      []UdpTask        // 无限增长
  overflowMode:  bool
  enqueueMu:     sync.Mutex
  overflowLen:   atomic.Int32
```

### enqueue 逻辑（line 61-86）

```
enqueue(task):
  lock enqueueMu
  if overflowMode:
    overflow = append(overflow, task)    // 无上限
    notifyWake()
    return
  select case ch <- task:                // 尝试写到 channel
    return
  default:                               // channel 满了！
    overflowMode = true
    overflow = append(overflow, task)    // 切换到 overflow mode
    notifyWake()
```

### convoy drain 顺序（line 142-224）

```
convoy():
  forever:
    1. popReadyTask():           // 先 drain channel，再 drain overflow
    2. select:
         case <-ch:              // 阻塞等待新任务
         case <-wake:            // overflow 通知
         case <-timer.C:         // GC 超时
```

`popReadyTask()` 优先 drain channel（non-blocking read），然后 drain overflow slice。

### overflow slice 是否无界？

**是**。overflow 是 Go `[]UdpTask`，无上限限制。当 convoy 执行速度 < enqueue 速度时：
1. channel (128) 先满
2. 进入 overflowMode，overflow slice 持续增长
3. 唯一限制：Go 内存（最终 OOM）

### 现有背压保护：只有 kernel socket buffer

| 层级 | 限制 | 说明 |
|------|------|------|
| **内核 socket buffer** | ~212KB（~140 个包） | 系统默认 SO_RCVBUF，无显式覆盖 |
| **routingEpochIngressGate** | 无 | 不限制正常操作中的并发数 |
| **channel** | 128 | 满后切换 overflow，不阻塞 enqueue |
| **overflow slice** | **无限制** | 可无限增长 |

### 关键风险评估

在不开 `udp-ordered-dispatcher` 时：

1. **无单 flow 的背压上限**：如果 convoy 执行慢（例如 upstream 慢、handlePkt 阻塞），而同一 flow 持续有包到来，overflow 会长到任意大。
2. **内存安全依赖内核丢包**：待 read 的包在内核 socket buffer 中排队。buffer 满后内核丢包，从而限制 enqueue 速率。但这个"背压"在 batch read 中不被感知——batch reader 一次 syscall 拿 8 个包，全部通过 tryAcquire → enqueue，不管 kernel buffer 是否接近满。
3. **跨 flow 隔离失败**：不同 flow 有自己的 channel（128）+ overflow（无界）。一个 hot flow 的 overflow 无限增长不影响其他 flow 的 enqueue——但所有 flow 共享同一个 Go 内存空间，最终一个 hot flow 可以 OOM 整个进程。

---

## 5. Reply 方向（上游 → 客户端）完整路径

### 路径概要

```
upstream proxy → proxy conn ReadFrom
  → UdpEndpoint.handleReceivedPacket()    [transport receiver]
    或 UdpEndpoint.startReadLoop()         [legacy read loop]
       → submitReply() / submitReplyFromReceiver()
         → submitReplyWithMode()
           → replyRuntime.slots (256)
              → udpReplyDispatcher.submit()
                 或 replySender goroutine (当 dispatcher=nil)
                    → handler → forwardUdpEndpointReplyToClient()
                       → sendPktWithResponseConnSlot()
                          → Anyfrom.WriteToUDPAddrPort()
                            → tproxy 回写客户端
```

### 当 udp-reply-dispatcher 关闭时（我们的关注点）

`newUdpEndpointReplyRuntime` 返回条件：
```go
if dispatcher == nil { return nil }   // udp_endpoint_pool.go:76-78
```

此时 `replyRuntime = nil`，`startReadLoop()` 走**备用路径**（line 1103-1130）：

```
if runtime != nil {     // false
  ...
}
// 备选路径：
replyCh = make(chan *udpEndpointReply, 256)   // udpEndpointReplyQueueSize
senderStop = make(chan struct{})
go ue.replySender(replyCh, senderStop, senderDone)
...
select {
  case replyCh <- queued:       ← 阻塞写！
    buf = pool.GetFullCap(consts.EthernetMtu)
  case <-senderStop:             ← 逃生口：handler 失败时关闭
    recycleUdpEndpointReply(queued, false)
    return
}
```

**重要**：`replyCh` 的 256 缓冲满后，select **阻塞**在 `replyCh <- queued`。这意味着：
- read loop 阻塞 → upstream proxy 的 `ReadFrom` 也阻塞
- 如果 proxy 走 TCP：TCP 流控向上游传播背压
- 如果 proxy 走 UDP：proxy UDP socket buffer 满后丢包

### 备用路径（replySender）的处理能力

```
replySender(replyCh, stop, done):
  batch = make([]*udpEndpointReply, 0, 8)
  for reply := range replyCh:
    batch = append(batch, reply)
    ...批量 drain...
    for each in batch:
      handler(ue, data, from)
        → forwardUdpEndpointReplyToClient()
          → sendPktWithResponseConnSlot()
            → Anyfrom.WriteToUDPAddrPort()  // 写回 client
```

handler 针对 sendPkt 失败**不主动关闭 endpoint**（line 511: 只 log and return nil）。所以 replySender 不会因为单个 sendPkt 失败就退出循环。

### reply 方向背压总结

| 层级 | 上限 | 说明 |
|------|------|------|
| **replyCh** | 256 | blocking send，满时阻塞 read loop |
| **read loop 阻塞** | 传播 | upstream proxy conn ReadFrom 阻塞 |
| **TCP flow control** | upstream | 如果 proxy 使用 TCP 传输，TCP 窗口提供端到端背压 |
| **sendPkt** | 系统 socket buffer | 写回 client 时可能阻塞在 kernel write |

**结论**：reply 方向的背压比 ingress 健全——replyCh 的 blocking send 在满时提供硬性背压，通过 read loop 传播到上游。

---

## 6. UdpEndpoint write queue / slot 机制（replyRuntime.slots）

### 数据结构

```go
type udpEndpointReplyRuntime struct {
  dispatcher        *udpReplyDispatcher
  slots             chan struct{}          // 容量 = udpEndpointReplyQueueSize (256)
  stop              chan struct{}
  admissionMu       sync.Mutex
  admissionClosed   bool
  admissions        int
  admissionsDrained chan struct{}
  failed            atomic.Bool
  tasks             sync.WaitGroup
  drainTracker      *controlPlaneDrainTracker
}
```

### slots channel 作为 semaphore

`submitReplyWithMode` 中使用 `slots` 作为计数信号量：

```go
// 非阻塞模式（transport receiver 路径）：
select {
  case runtime.slots <- struct{}{}:
  case <-runtime.stop:
    return false, false
  default:                                 // 满了就直接 drop
    releaseUdpEndpointReply(reply, release)
    return false, true                     // 不关闭 endpoint
}

// 阻塞模式（startReadLoop 路径）：
select {
  case runtime.slots <- struct{}{}:
  case <-runtime.stop:
    return false, false
}
```

### release 时机

```go
complete := func() {
  releaseUdpEndpointReply(reply, release)  // 释放包数据
  <-runtime.slots                          // 释放 slot
  drainRelease()
  runtime.tasks.Done()
}
```

一个 slot 在 handler（sendPkt）**完全执行完后**才释放。所以并发上限 = min(256, 上游读入速率)。

---

## 7. 核心结论

### ingress 方向（client → dae → upstream）

| 背压层 | 限制值 | 是否够用 | 理由 |
|--------|-------|---------|------|
| 内核 SO_RCVBUF | ~212KB | ⚠️ 依赖系统默认 | 未显式配置，默认值在高速率下可能不足 |
| routingEpochIngressGate | 无上限 | ❌ 不是背压 | 只用于 shutdown drain |
| convoy channel | 128 | ⚠️ 切换到 overflow 后无效 | 满后 overflowMode=true |
| **convoy overflow** | **无上限** | **❌ 无背压** | slice 无限增长，可 OOM |

**不开启 udp-ordered-dispatcher 时，convoy 路径的 overflow slice 无上游背压保护。** 唯一间接限制是内核 socket buffer 的容量——但 batch read 一次取 8 个包，processPacket 逐个 tryAcquire + enqueue 时，这些包已经在用户态内存中了。overflow 的唯一上限是 Go 进程的可用内存。

### reply 方向（upstream → dae → client）

| 背压层 | 限制值 | 是否够用 | 理由 |
|--------|-------|---------|------|
| replyCh / slots | 256 | ✅ 有限 | blocking send 提供硬性背压 |
| read loop 阻塞 | 向上游传播 | ✅ 端到端 | proxy conn ReadFrom 阻塞 |
| sendPkt | 系统 buffer | ⚠️ 但 handler 不 treat error as fatal | sendPkt 失败仅 log，不关闭 endpoint |

**reply 方向的背压比 ingress 健全得多。** 当 udp-reply-dispatcher 关闭时，dedicated replySender + blocking replyCh（256）足以防止内存无限增长，并将背压传播到上游 proxy conn。

### 建议

1. **给 overflow slice 加上限**：当 `len(overflow) > N`（如 1024）时，drop 队头或新包。这可以防止单个 hot flow 耗尽进程内存。
2. **给 ingress UDP socket 显式设置 SO_RCVBUF**：防止默认值在高速率场景下过早丢包（或者让丢包更可控）。
3. **考虑 gate 做正常情况下的硬限制**：虽然 `routingEpochIngressGate` 目前只为 shutdown 设计，可以增加一个 `tryAcquireWithLimit(max)` 模式，在正常操作中限制 inflight 包数。

### 针对原始问题的回答

> "在不开 udp-ordered-dispatcher / udp-reply-dispatcher 的情况下，convoy 路径的 overflow slice 是否已经有足够的上游背压保护？"

**否。** overflow slice 无上限。上游背压仅来自内核 SO_RCVBUF（默认 ~212KB），但 batch read 可以一次将 buffer 中的包全取到用户态，这些包全部通过 tryAcquire 后进入 overflow，不受任何用户态速率限制。单 flow hot key 有 OOM 风险。reply 方向相反，有完善的 blocking channel 背压。
