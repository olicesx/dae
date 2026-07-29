---
sprint: 3
sprint_theme: "Memory optimization via H5 (bench + memprofile dual verification)"
qa_owner: Ivy
verdict: PASS
date: 2026-07-29
branch: kdae
head: 2532f453
content_language: bilingual
prev_signoff: qa-signoff-2.md
---

# QA Sign-off — Sprint 3（基于 H5 的内存优化：bench + memprofile 双验证）

> QA：Ivy。验证范围与 gate 清单见 [../sprint-3/plan.md](../sprint-3/plan.md#gates)。
> Dev 产出与 H5 memprofile 决定性对比见 [../sprint-3/progress.md](../sprint-3/progress.md)。

## 结论 / Verdict

| 项 | 结果 |
|---|---|
| **Verdict** | **PASS** ✅ |
| local_gate | ✅ 全过（orchestrator L2 已验证，QA 未重跑；VET_EXIT=0 / BUILD_EXIT=0 二次确认） |
| ci_gate | ✅ `make ebpf-test` 本机实跑 8/8 PASS（3.224s，H1 持续）+ `make dae` EXIT=0（ELF x86-64 二进制）+ `make ebpf-sync-check` EXIT=0 |
| manual_gate | ✅ `make dae` 产出二进制 + `dae validate`（example/empty）EXIT=0 + bench allocs/op 18→18 持平（H5 memprofile 为决定性证据） |
| H5 memprofile 复核 | ✅ `strings.ToLower` / `errStrLower` / `containsFoldASCII` 三者在 pprof alloc_objects top 30 **均未出现**（TOLLOWER_MATCH_COUNT=0）→ errStrLower 路径 ToLower 分配完全消除 |
| Issue 清单 | 空（T1 为 effective_small，bulk inherent 5 项已文档化为非 silent no-op） |

**一句话理由 / One-liner**：三 gate 全过。T1 改动（`errStrLower` → `containsFoldASCII` 零分配大小写不敏感匹配）的改进效果由 H5 memprofile 决定性证据保证——`strings.ToLower` cum 32768 allocs(1.19%) → 0（从 pprof top 消失）；bench 18→18 持平符合预期（errStrLower 在错误路径 + bench 高方差，memprofile 才是决定性证据，非 bench 数字）。H5 在 Producer 阶段即过滤 harness-noise task（Sprint 3 = 0 个，Sprint 2 = 1 个 T2 事后才发现）。

---

## 1. 任务交付复核 / Task Delivery Review

1 任务：T1 effective_small。code commit 1/2（commit budget 2，hard_cap=10，未超）。

| Task | 类型 | 文件 | 交付 | commit |
|---|---|---|---|---|
| T1 | effective_small | control/udp_endpoint_pool.go | `errStrLower`（`strings.ToLower(err.Error())`）→ `containsFoldASCII`（ASCII 路径 inline 'A'-'Z' 折叠零分配，非 ASCII 字节回退 `strings.Contains(strings.ToLower(s), substr)` 保证 Unicode 完全等价）；删除 `errStrLower` 函数，3 个 `Contains` 调用点改为 `containsFoldASCII` | `2532f453` |

**bulk inherent 文档化**（OQ-S3-2 闭环）：context.WithDeadlineCause / registerEndpoint / time.NewTimer / createEndpointLocked / err.Error() 五项记为 inherent no-op（消除即破坏语义：拨号超时机制 + endpoint 对象生命周期 + map 索引 + 错误消息构建），Dev 仅文档化未改语义，progress.md §Bulk inherent 各附 1 句论证。

---

## 2. Gate 执行矩阵 / Gate Execution Matrix

### 2.1 local_gate（本机必过，orchestrator L2 已全过，QA 未重跑避免重复消耗）

| Gate | 命令 | 结果 |
|---|---|---|
| go_vet | `go vet -tags=$BT ./...` | ✅ Dev L2 已过；QA 二次确认 VET_EXIT=0 |
| go_build | `go build -tags=$BT ./...` | ✅ Dev L2 已过；QA 二次确认 BUILD_EXIT=0 |
| go_test | `go test -tags=$BT ./control/... ./component/...` | ✅ Dev L2 已过（control 25.5s + component 全 ok） |
| go_test_race | `go test -tags=$BT -race ./control/...` | ✅ Dev L2 已过（control 28.0s，T1 涉及读循环 race 必跑） |
| benchmark_no_regression | allocs/op 对照 | ✅ 见 §3 |
| memprofile_review | `pprof -top -sample_index=alloc_objects` | ✅ Dev L2 已过 + QA 复核见 §4 |

> Deterministic-first：全部门禁为机器判定 pass/fail，无 LLM-as-judge 场景。

### 2.2 ci_gate（H1：本机实跑 runs，非 ignored）

| Gate | 命令 | 结果 | 说明 |
|---|---|---|---|
| F1 make ebpf | `make ebpf` | ✅ MAKE_EBPF_EXIT=0 | 生成 bpf 绑定（control 包必需） |
| ebpf_test | `make ebpf-test` | ✅ PASS（本机实跑） | 8/8 PASS（3.224s），覆盖 routing/conntrack/wan-egress/epoch |
| make dae | `make dae` | ✅ MAKE_DAE_EXIT=0 | 产出 ELF 64-bit LSB executable, x86-64 |
| ebpf_sync_check | `make ebpf-sync-check` | ✅ EBPF_SYNC_EXIT=0 | progress 标 pending 由 QA 闭环：`git diff --exit-code` 干净（无 C 结构体改动） |
| ebpf_lint | `make ebpf-lint` | N/A | 无 `.c` 改动（T1 仅 .go） |

**`make ebpf-test` 实跑结果**（WSL2 kernel 6.18，root，timeout=180s）：

```
--- PASS: TestBpfBugsVerification (0.43s)
--- PASS: Test (0.41s)
--- PASS: TestWanEgressDirectMarkReroute (0.37s)
--- PASS: TestWanEgressTcpNonSynCachedProxyRedirect (0.38s)
--- PASS: TestWanEgressTcpNonSynStatelessPassthrough (0.38s)
--- PASS: TestWanEgressTcpSynRedirectTrack (0.41s)
--- PASS: TestWanEgressUdpRedirectTrack (0.40s)
--- PASS: TestConntrackArgsScratchReset (0.43s)
PASS
ok  github.com/daeuniverse/dae/control/kern/tests   3.224s
```

**PASS_COUNT=8 / FAIL_COUNT=0**。与 Sprint 1/2 完全一致 → Sprint 3 的 Go 侧改动（T1 udp_endpoint_pool.go）对 eBPF 数据平面**零影响**（预期正确：Sprint 3 未碰任何 `.c`）。

### 2.3 manual_gate（playthrough 类）

| 检查 | 命令 | 结果 |
|---|---|---|
| 完整构建 | `make dae` | ✅ 产出 `dae`：ELF 64-bit LSB executable, x86-64，stripped（`-ldflags "-s -w"`） |
| 配置加载（完整） | `./dae validate -c /tmp/qa3-example.dae`（0600 副本） | ✅ VALIDATE_EXAMPLE_EXIT=0 |
| 配置加载（最小） | `./dae validate -c /tmp/qa3-empty.dae`（0600 副本） | ✅ VALIDATE_EMPTY_EXIT=0 |
| benchmark 等价性 | 见 §3 | ✅ 18→18 持平（符合预期） |
| H5 memprofile 复核 | 见 §4 | ✅ ToLower 路径消除 |
| 完整透明代理 playthrough | — | ⚠️ **manual-limited**（同 Sprint 1/2，见 §5） |

---

## 3. Benchmark 等价性复核 / Benchmark Equivalence（H2 verification）

QA 实跑（`-tags=trace -benchmem -benchtime=300ms -run='^$'`），与 progress.md 基线对照：

| Benchmark | 基线 allocs/op | Dev 改后 | QA 复测 | Δ B/op | 判定 |
|---|---|---|---|---|---|
| BenchmarkUdpProxyDial/cache=miss | 18 (5230 B/op) | 18 (5238 B/op) | **18 (5226 B/op)** | ΔB 在 ±10 噪声内 | ✅ 持平（符合预期） |
| BenchmarkUdpProxyDial/cache=hit | 0 | 0 | **0** | — | ✅ 无回归（池化命中零分配） |

**18→18 持平的正当性论证**（OQ-S3-1 闭环）：
- `errStrLower` 在错误路径（ICMP-refused），bench 是否真实触发 refused 取决于 read-loop 非确定性迭代次数；
- progress.md 已证实 isConnectionRefused 在 bench 中**确实被调用**（before cum 229377 / after cum 393218 allocs，~3-5 次/op），ToLower 路径 32768 allocs 真实存在；
- bench allocs/op 18→18 持平系**高方差噪声主导**（无关函数 registerEndpoint 9%→13.5%、closeQuicBenchmarkEndpoint 11%→7.6% 同期同向波动佐证），**非路径未触发**；
- **memprofile（§4）才是决定性证据**：ToLower 路径 32768 对象分配在 after 完全消失。

> H5 论证要点：bench 数字非改进生效的唯一判据，错误路径 alloc 改进的验证须以 memprofile 为准，避免 bench 高方差误判为 no-op。

---

## 4. H5 memprofile 决定性复核 / H5 Decisive Re-verification

**方法**：QA 重跑 T1 after memprofile（`/tmp/qa3-t1-after.mem`），grep 搜索 `tolower|errstrlower|containsfoldascii`。

| 检查项 | 结果 |
|---|---|
| ToLower/errStrLower/containsFoldASCII 在 pprof alloc_objects top 30 | **均未出现**（TOLLOWER_MATCH_COUNT=0，grep 退出码 1） |
| `isConnectionRefused` flat | 131073 (5.49%) —— 存在（err.Error() inherent，见 §1 bulk 文档化） |
| ToLower 路径的 MakeNoZero / genSplit | 未出现（Dev L2 before/after 对比已证实 cum 32768→0） |

**pprof top 25 关键项**（QA 复测，与 progress.md after 数据一致）：

```
flat  flat%   sum%        cum   cum%
343623 14.40% 14.40%     343623 14.40%  runUdpProxyDialBenchmark.func1   (bench harness)
289634 12.14% 26.54%     289634 12.14%  registerEndpoint                 (inherent, 已文档化)
230951  9.68% 36.22%     468146 19.62%  closeQuicBenchmarkEndpoint       (bench harness)
210662  8.83% 45.04%     294931 12.36%  context.WithDeadlineCause        (inherent, 已文档化)
204251  8.56% 53.60%    1237320 51.85%  createEndpointLocked             (inherent, 已文档化)
162289  6.80% 67.73%     237195  9.94%  time.NewTimer                    (inherent, 已文档化)
131073  5.49% 86.17%     131073  5.49%  isConnectionRefused              (err.Error() inherent，ToLower 已消除)
```

**H5 改进生效证据**：top 中残留的 5 项高 flat% 函数（registerEndpoint / WithDeadlineCause / createEndpointLocked / NewTimer / isConnectionRefused）**全部**为 progress.md §Bulk inherent 文档化的内禀分配，**无任何可消除 residual**。对比 Sprint 2 T2 事后才发现 bench harness 噪声，Sprint 3 在 Producer 阶段即过滤 → **0 个 harness-noise task**（见 §6）。

---

## 5. manual-limited 说明 / Manual Playthrough Limitation

**完整透明代理 playthrough 本机受限**（同 Sprint 1/2）：需真实出口节点 + 上游代理凭据 + 特权网络命名空间 + 完整路由/iptables 配置；WSL2 非生产部署形态。

**不降级为 CONDITIONAL 的理由**：
1. Sprint 3 为**语义保持的零分配重写**（`isConnectionRefused` 返回值对所有输入逐位一致，plan safety_condition 兑现），非新功能 → 不需新功能式端到端 playthrough；
2. 行为正确性由三层 deterministic 证据充分保证：
   - Go test/race 覆盖 T1（udp_endpoint_pool.go，含读循环 race 验证）；
   - `make ebpf-test` 8/8 PASS，Sprint 3 无 `.c` 改动 → eBPF 数据平面字节级等价；
   - H5 memprofile 决定性证据：ToLower 路径 32768 allocs 完全消除。
3. progress.md 无 `❌ Blocked` 区块，无 P0 缺陷。

---

## 6. H5 Eval 回归验证 / H5 Eval Regression Verification

> plan.md `eval_regression_verification` 要求显式对照。

### H5（新项首次应用）— `harness.*allocs.*flat=0`

> regression_signal：harness 噪声 task 在 Producer 阶段过滤；flat=0 即改进生效。

| 维度 | Sprint 2（H5 前） | Sprint 3（H5 应用后） |
|---|---|---|
| harness-noise task 在 Producer 阶段过滤数 | 0（T2 在 Dev 阶段才发现，浪费 token） | **1**（WriteToBufferFlush 60 allocs/3.6MB 在 Producer 阶段 memprofile 判为 95.73% harness，过滤不设 task） |
| 设 task 数 | 3（T1/T2/T3） | **1**（T1） |
| harness-noise task 数（Dev 阶段才发现的） | 1（T2 honest no-op，memprofile 事后证实） | **0**（H5 在 Producer 即过滤，无事后发现） |
| no-op 率 | 33%（1/3） | **0%**（T1 effective_small 已验证生效） |

**结论 / Conclusion**：H5 改进**验证生效**。Producer 阶段 memprofile 分类（runtime-context.md §H5 四候选 A/B/C/D）将最大热点 WriteToBufferFlush（60 allocs/3.6MB）判为 95.73% harness noise 而过滤，**从源头**消除 Sprint 2 T2 式 no-op（事后才发现，浪费 Dev 阶段 token）。Sprint 3 = H5 正确应用的预期形态（thin Sprint，1 task effective_small）。

### H1 — `ci_gate.*ignored`

| 项 | Sprint 1 | Sprint 2 | Sprint 3 |
|---|---|---|---|
| plan gate 标注 | `local: ignored`（保守） | `local: runs` | `local: runs` |
| QA 实跑 | PASS（3.1s） | PASS（3.177s） | **PASS（3.224s）** |
| regression_signal 匹配 | ✅ 命中 | ❌ 不再匹配 | ❌ 不再匹配 |

**结论**：H1 持续生效（连续 2 Sprint ci_gate 实跑 PASS，无回归）。

### H2 — `no_op_tasks.*[4-9]/`

| 项 | Sprint 1 | Sprint 2 | Sprint 3 |
|---|---|---|---|
| 任务数 | 7 | 3 | **1** |
| no-op 数 | 4 | 1（T2 honest） | **0**（T1 effective_small + bulk inherent 文档化非 task） |
| no-op 率 | 57% | 33% | **0%** |
| regression_signal 匹配 | ✅ 命中 | ❌ | ❌ |

**结论**：H2 持续生效（bench 驱动选文件 + H5 memprofile 过滤）。

### H3 — `EXIT_(BUILD|TEST)=True`

Sprint 3 全程脚本化（`tmp/qa-sprint3.sh`、`tmp/sprint3-gates.sh`、`tmp/sprint3-baseline.sh`、`tmp/sprint3-env.sh` 等），所有 gate exit code 可靠捕获。eval 通过 ✅。

---

## 7. Issue 清单 / Issue List

**空 / Empty。** 理由：
- T1 改动通过全部 deterministic gate + H5 memprofile 决定性证据；
- bench 18→18 持平为错误路径 + 高方差噪声主导的正当现象（非缺陷），memprofile 证实 ToLower 路径真实消除；
- bulk inherent 5 项已文档化为非 silent no-op（OQ-S3-2 闭环），不提 Issue；
- `make ebpf-test` 8/8 PASS（Sprint 3 无 `.c` 改动，eBPF 数据平面零影响）；
- 无任何真实缺陷需上报。

---

## 8. Sprint+1 候选（L4 Hill Climbing 输入）/ Sprint+1 Candidates

> 由 QA 在 progress.md「Sprint+1 候选」段记录，此处引用不重复。

| ID | 候选项 | 来源 | 说明 |
|---|---|---|---|
| — | sniffing lifecycle 重构（NewStreamSniffer/async-read/StreamSniffer 池化） | Sprint 1/2/3 三次确认 | 跨 3 Sprint 数据点强信号：每次均因超语义等价边界被排除。建议 Sprint+1 改主题为"lifecycle refactor"（非 semantic-preserving），明确允许跨调用存活的对象池化。 |
| — | daedns client.go bench 补充（Sprint 2 OQ-S2-2 滚动） | Sprint 2 | T1 收益靠论证无 bench 量化；可选补充（避免 scope 膨胀）。 |
| — | H6：verification-fidelity-check.ps1 对 Go 项目假阴性 | Sprint 3 drift-check | 假设 src/ 布局，Go 项目 PASS no_source_changes；手动 git-log 为权威。待 harness backlog 处理。 |

**Harness backlog 更新**：H1/H2/H3 持续生效（连续 2-3 Sprint eval 通过）；H5 首次应用验证生效；H6 待处理（fidelity check 对 Go 项目假阴性）。

---

## 9. Reflexion / 经验沉淀

- **H5 memprofile 优于 bench 数字**（错误路径场景）：errStrLower 在 ICMP-refused 错误路径，bench 高方差致 allocs/op 18→18 持平，但 memprofile 严格证实 ToLower 路径 32768 对象分配消除。**lesson**：对错误路径的零分配改进，gate 应优先 memprofile（cum flat 消失为硬证据），bench 数字为辅助。
- **Producer 阶段过滤优于 Dev 阶段发现**：Sprint 2 T2 在 Dev 阶段才发现 bench harness no-op（浪费 token）；Sprint 3 在 Producer 阶段 memprofile 分类即过滤 WriteToBufferFlush（60 allocs/3.6MB harness noise），Dev 阶段 0 个 no-op task。H5 闭环验证生效。
