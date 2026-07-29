# Sprint 2 Hill Climbing Report

> 生成：2026-07-29（QA 签署 PASS 后，orchestrator L4 自执行）
> Sprint 主题：语义不变的代码精简（bench 驱动 + OQ4）

## Trace 聚合

| 指标 | Sprint 1 | Sprint 2 | 趋势 |
|------|----------|----------|------|
| trace_count | 7 | 3 | — |
| silent_failures | 0 | 0 | 持平（优） |
| goal_drifts | 0 | 0 | 持平（优） |
| l2_failures | 0 | 0 | 持平（优） |
| over_budget | 0 (4/5) | 0 (2/2) | 持平（优） |
| no_op_tasks | 4/7 (57%) | 1/3 (33%) | **↓ 改善（H2 生效）** |
| L2 retry | 0 | 0 | 持平（优） |

## H1-H4 Eval 对照（plan.md 要求显式）

| 改进项 | Sprint 1 基线 | Sprint 2 实测 | 结论 |
|--------|--------------|--------------|------|
| **H1** ci_gate 探测 | `ebpf_test: ignored`（过保守） | `make ebpf-test` 实跑 8/8 PASS 3.177s，plan 标 runs | ✅ 生效 |
| **H2** bench 驱动选文件 | grep 静态扫描，57% no-op | bench -benchmem 实测排序，33% no-op | ✅ 生效 |
| **H3** WSL 命令脚本化 | inline `$` 误报（L7） | 全程 tmp/*.sh，gate exit 可靠 | ✅ 生效 |
| **H4** target_files 含关联文件 | A5 严守 router.go 错失 client.go | T1 client.go 纳入（OQ4 解决） | ✅ 生效 |

## 模式识别

**Sprint 2 比 Sprint 1 更干净**：no-op 率从 57% 降到 33%，且唯一的 no-op（T2）有 memprofile 硬证据。

**关键新发现（L9）**：bench 的 `allocs/op` 可能是 **harness 噪声而非生产分配**。T2 的 RelayCopyLoop_1MB=9 allocs/op，memprofile 证实 9 个全来自 `bytes.NewReader`(18.97%) + `bytes.Buffer.growSlice`(13.46%) via benchConn.Write，生产 `relayCopyLoop`/`relayCopyDirect` flat=0（已全池化）。这意味着 **H2 的 bench 驱动需要 memprofile 交叉验证**才能区分"真生产热点"与"bench 工件"。

## 改进项（写入 harness-backlog）

### H5 [scope] bench + memprofile 双验证（H2 增强）
- **现象**：T2 的 bench allocs/op=9 全是 harness 噪声（memprofile 证实生产 flat=0），导致 Dev 花时间分析后才诚实 no-op
- **改进**：H2 选出热点后，Dev 实施前先跑 `-memprofile` 确认 allocs 来自生产路径而非 bench harness；若全为 harness 噪声 → 直接判 no-op 不设 task
- **预期收益**：进一步降低 no-op 率，减少 Dev 在 harness 噪声上的分析 token

## Sprint+1 候选（功能 backlog，非 harness）

- **T3 剩余非密码学分配**（sniffing QUIC）：`ExtractCryptoFrameOffset` 经 `s.quicCryptos` 跨调用存活、`NewLinearLocator` 装箱入 Locator 接口——需更深重构（接口/生命周期调整），**超本 Sprint 语义等价边界**，留作后续

## 跨 Sprint 复利展望（2 个 Sprint 数据点）

| 维度 | Sprint 1 → Sprint 2 |
|------|---------------------|
| no-op 率 | 57% → 33%（H2 生效） |
| harness 改进应用 | 0 → 4 项全生效 |
| lessons 积累 | L1-L8 → L1-L9（+memprofile 区分） |
| ci_gate 误判 | ignored → runs（H1 生效） |

第 3 个 Sprint 后可量化 no-op 率是否继续下降（目标 < 20%）。
