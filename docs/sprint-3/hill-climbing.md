# Sprint 3 Hill Climbing Report

> 生成：2026-07-29（QA 签署 PASS 后，orchestrator L4 自执行）
> Sprint 主题：内存优化 via H5（bench + memprofile 双验证）

## Trace 聚合

| 指标 | Sprint 1 | Sprint 2 | Sprint 3 | 趋势 |
|------|----------|----------|----------|------|
| trace_count | 7 | 3 | 1 | 矿脉收敛 |
| silent_failures | 0 | 0 | 0 | 持平（优） |
| goal_drifts | 0 | 0 | 0 | 持平（优） |
| l2_failures | 0 | 0 | 0 | 持平（优） |
| over_budget | 0 (4/5) | 0 (2/2) | 0 (1/2) | 持平（优） |
| no_op_tasks | 4/7 (57%) | 1/3 (33%) | 0/1 (0%) | **↓ 持续改善** |
| harness-noise task | — | 1 (T2) | **0** | **H5 生效** |
| L2 retry | 0 | 0 | 0 | 持平（优） |

## H1-H5 Eval 对照（3 Sprint 复利趋势）

| 改进项 | 引入 | 应用 | Sprint 3 验证 |
|--------|------|------|--------------|
| H1 ci_gate 探测 | S1 L4 | S2 | ✅ 持续 runs（make ebpf-test 8/8 PASS 3.224s） |
| H2 bench 驱动 | S1 L4 | S2 | ✅ 持续（全量 bench 选热点） |
| H3 脚本化 | S1 L4 | S2 | ✅ 持续（全程 tmp/*.sh） |
| H4 关联文件 | S1 L4 | S2 | ✅ 持续 |
| **H5 bench+memprofile 双验证** | **S2 L4** | **S3** | ✅ **生效**（见下） |

### H5 生效证据

- **Sprint 2（H5 前）**：bench 选出 T2（tcp_copy 9 allocs/op）→ Dev 实施时 memprofile 才发现全是 harness 噪声 → 1 个事后 no-op task（浪费 Dev 分析 token）
- **Sprint 3（H5 后）**：Producer 阶段就跑 memprofile，**源头过滤**最大热点 WriteToBufferFlush（60 allocs/3.6MB，memprofile 证 95.73% 是 net.IPv4/ listenTCPProto harness）→ 不设 task → **0 harness-noise task**

### H5 的额外洞察：memprofile > bench allocs/op 精确性

Sprint 3 T1 的 bench `UdpProxyDial/cache=miss` 18→18 **持平**（看似无效），但 memprofile 决定性证明 `strings.ToLower` cum 32768 allocs → 0（完全消除）。原因：errStrLower 在**错误路径**（ICMP refused），非每次 bench 迭代触发，且 bench 高方差（30-50% 波动）掩盖了小占比分配的变化。

**结论**：bench allocs/op 适合"粗筛"（H2），memprofile 适合"精确定位 + 验证消除"（H5）。两者互补，不可互替。

## H6（Sprint 3 新发现，已记入 harness-backlog Pending）

verification-fidelity-check.ps1 假设 `src/` 布局（Rust/sync_watcher 起源），对 dae（Go，control/**/component/** 布局）返回假阴性 `PASS no_source_changes`。Sprint 2 手动 git-log 交叉验证恰好正确，但未来有漏报风险。改进：源码检测改为语言无关（按 git diff 文件扩展名）。

## 矿脉评估：内存优化空间近枯竭

3 个 Sprint 后，dae 的内存分配优化矿脉已基本耗尽：

| Sprint | 有效改动 | 诚实 no-op | 结论 |
|--------|---------|-----------|------|
| S1 | A1/A2/A4（3） | A3/A5/B1/B2（4，已最优） | 主矿脉 |
| S2 | T1/T3（2） | T2（harness 噪声） | 次矿脉 |
| S3 | T1（1，errStrLower） | bulk inherent（5，不可消） | 尾矿 |

H5 memprofile 全量扫描后，剩余热点分类：
- **harness 噪声**（WriteToBufferFlush 95.73%）→ 不可优化（非生产代码）
- **密码学内禀**（QUIC 59% hmac/sha256/hkdf）→ 不可优化（算法本质）
- **lifecycle 边界**（StreamSniffer/async-read 装箱）→ 可优化但**超语义等价边界**（需接口/生命周期重构）

## Sprint+1 候选（功能 backlog，非 harness）

- **主题建议：lifecycle refactor**（明确**非**语义保持，需新 Sprint 类型）
  - sniffing `NewStreamSniffer`（SniffTcp_TLS 11% flat）+ async-read goroutine（19%）池化
  - T3 剩余：`ExtractCryptoFrameOffset` 跨调用存活、`NewLinearLocator` 装箱入 Locator 接口
  - ⚠️ 这些改动**改变接口/生命周期结构**，超出前 3 个 Sprint 的"语义等价"约束，需单独评估

## 跨 Sprint 复利总结（3 Sprint 数据点）

| 维度 | 演进 |
|------|------|
| no-op 率 | 57% → 33% → 0%（H2+H5 叠加生效） |
| harness 改进 | 0 → H1-H4 → H1-H5（+H6 pending） |
| 方法论成熟度 | grep 静态 → bench 实测 → bench+memprofile 双验证 |
| lessons | L1-L8 → L9（+memprofile 区分） |

**Nadella 复利效应实证**：harness 改进（H1-H5）每个都基于前序 Sprint 的失败模式，形成可量化的学习曲线。论文证据「build learning loops early... advantage hard to replicate」在第 3 个 Sprint 得到验证——no-op 率归零、0 harness-noise task、0 L2 retry。
