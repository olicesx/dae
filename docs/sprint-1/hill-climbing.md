# Sprint 1 Hill Climbing Report

> 生成：2026-07-29（QA 签署 PASS 后，orchestrator L4 自执行）
> Sprint 主题：语义不变的代码精简优化（Go 内存分配 + eBPF C 数据平面精简）

## Trace 聚合

| 指标 | 值 |
|------|-----|
| trace_count | 7（A1-A5 + B1-B2） |
| silent_failures | 0 |
| goal_drifts | 0 |
| l2_failures | 0 |
| over_budget | 0（commits 4/5） |
| no_op_tasks | 4（A3/A5/B1/B2，均诚实且有代码分析论证） |
| effective_tasks | 3（A1/A2/A4，有真实代码改动） |
| L2 retry 次数 | 0（所有 gate 一次过） |

## 模式识别

**本 Sprint 极干净**：零失败模式（silent_failure / goal_drift / l2_failed / over_budget 全为 0）。所有 no-op 任务都有充分的代码分析论证（IR 分析 / bench 实测 / grep 确认），属于"经验证已最优"，不是 silent failure。

**唯一结构性观察**：no-op 率 57%（4/7）。这反映前期静态扫描（grep make/append）选文件不够精准——静态存在的分配调用 ≠ 运行时热路径分配。A3 的热路径已 0 allocs/op、B1/B2 的 lookup 经 clang IR 确认无真冗余，都是扫描阶段无法预知的。

## 改进项（已写入 /memories/repo/harness-backlog.md）

### H1 [scope] Producer gate 可行性探测
- **现象**：Producer 把 ci_gate `make ebpf-test` 标 ignored（理由 WSL2 kernel 6.18 非 CI matrix），但 QA 实测本机能跑且 20+ 用例全过（3.1s）
- **改进**：Producer 规划时先尝试轻量实跑 ci_gate，能跑则不标 ignored
- **预期收益**：减少 CONDITIONAL 误判，签署置信度从"依赖 CI"提升到"本机实证"

### H2 [scope] bench 驱动选文件
- **现象**：7 任务中 4 个 no-op（57%），grep 静态扫描选的文件部分运行时已最优
- **改进**：扫描阶段跑 `go test -bench=. -benchmem ./...`，按 allocs/op 实测排序，优先选有非零分配的文件
- **预期收益**：降低 no-op 率，减少 token 浪费在"经验证已最优"的分析上

### H3 [tool] WSL 命令脚本化
- **现象**：PowerShell 内联 `$?`/`$()` 被自身解析，导致 gate exit code 误报为 True（lessons-learned L7）
- **改进**：多行命令一律写 `tmp/*.sh` 脚本再 `wsl bash <script>`，禁 inline shell `$` 变量
- **预期收益**：gate 验证可靠性，避免误判

### H4 [scope] target_files 含关联文件
- **现象**：A5 严守 router.go，但真正 per-query buffer 优化机会在 client.go（OQ4），因 target_files 边界过严而无法触及
- **改进**：当扫描发现优化点跨文件但同模块同 pool 模式时，Producer 把关联文件纳入 target_files
- **预期收益**：避免"机会在隔壁却不能动"

## Sprint+1 候选（功能 backlog，非 harness）

- **OQ4**: daedns `client.go` per-query buffer 池化
  - `sendStreamDNS` 的 req/lengthBuf/respBuf（client.go:556-571）
  - `queryHTTPS` 的 `io.ReadAll`（client.go:542）
  - `lookupType` 的 `msg.Pack` → `PackBuffer`（client.go:253）
  - 方案：lengthBuf 上栈 `[2]byte`、req/respBuf 沿用 `udpDNSBufPool` 模式

## 跨 Sprint 复利展望

首个 Sprint 建立了基线：
- harness-backlog 有 4 项可应用改进
- lessons-learned 有 L1-L8（含 PowerShell 转义陷阱、WSL2 ebpf-test 可行性等可复用经验）
- benchmark 基线（allocs/op + verifier instruction count）已记录，后续 Sprint 可量化趋势

论文证据（Nadella）：「build learning loops early... will build an advantage that's hard to replicate」。第 3 个 Sprint 后可量化 no-op 率 / silent_failure 率下降趋势。
