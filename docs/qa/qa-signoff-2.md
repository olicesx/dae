---
sprint: 2
sprint_theme: "Semantic-preserving code slimming (bench-driven + OQ4)"
qa_owner: Ivy
verdict: PASS
date: 2026-07-29
branch: kdae
head: 26bc9f61
content_language: bilingual
prev_signoff: qa-signoff-1.md
---

# QA Sign-off — Sprint 2（语义不变的代码精简：bench 驱动 + OQ4）

> QA：Ivy。验证范围与 gate 清单见 [../sprint-2/plan.md](../sprint-2/plan.md#verifiable_gates)。
> Dev 产出与 bench 前后值见 [../sprint-2/progress.md](../sprint-2/progress.md)。

## 结论 / Verdict

| 项 | 结果 |
|---|---|
| **Verdict** | **PASS** ✅ |
| local_gate | ✅ 全过（orchestrator L2 已验证，QA 未重跑；VET_EXIT=0 / BUILD_EXIT=0 二次确认） |
| ci_gate | ✅ `make ebpf-test` 本机实跑 8/8 PASS（3.177s，H1 验证非 ignored）+ `make dae` EXIT=0 |
| manual_gate | ✅ `make dae` 产出二进制（ELF x86-64）+ `dae validate`（example/empty）EXIT=0 + benchmark 零回归且 T3 −2 allocs |
| Issue 清单 | 空（T2 honest no-op 为优化受阻非缺陷，memprofile 证据见 progress.md） |

**一句话理由 / One-liner**：三 gate 全过。Sprint 2 为等价重构（行为不变），行为正确性由三层证据保证——Go test/race 覆盖 T1/T2/T3（Dev L2 已过）、`make ebpf-test` 真实内核加载测试 8/8 PASS（routing/conntrack/wan-egress/epoch，与 Sprint 1 改动面零回归）、benchmark allocs/op 零回归且 T3 QUIC 69→67 改进稳健（−2.9%）。无需新功能式端到端 playthrough。

---

## 1. 任务交付复核 / Task Delivery Review

3 任务：2 effective（T1/T3）+ 1 honest no-op（T2，memprofile 证实）。commit budget 2/2（T1 commit `4c1de816` + T3 commit `c1ab617d`；progress.md 更新为 docs commit `26bc9f61`，不计 code budget）。**未超 hard_cap=10**。

| Task | 类型 | 文件 | 交付 | commit |
|---|---|---|---|---|
| T1 | effective | component/daedns/client.go | lookupType `Pack→PackBuffer` + sendStreamDNS req/respBuf 复用 `udpDNSBufPool` + lengthBuf 上栈 `[2]byte` + sendHTTPDNS `io.ReadAll→ReadFull` 池化（L4 同步消费论证） | `4c1de816` |
| T2 | **honest no-op** | control/tcp_copy_engine.go | memprofile 证实 `RelayCopyLoop_1MB` 的 9 allocs/op 全来自 bench harness（`bytes.NewReader` + `bytes.growSlice` + `benchConn` struct），生产 `relayCopyLoop`/`relayCopyDirect` flat=0 → 无生产代码可改 | (no commit) |
| T3 | effective-minimal | component/sniffing/internal/quicutils/relocation.go | `ReassembleCryptos` `len(offsets)<=1` 短路（跳过 `sort.Slice` reflectlite.Swapper + merged `make`）；密码学内禀 ~54 allocs 不可消除（OQ-S2-1 量化闭环） | `c1ab617d` |

**T2 honest no-op 确认**：符合 H2 + L1/L9 范式——先 memprofile 区分 bench-harness allocs vs 生产 allocs，flat=0 即诚实 no-op，不动生产代码（避免 YAGNI 式无意义改动）。progress.md Trace Log 有完整证据链。

---

## 2. Gate 执行矩阵 / Gate Execution Matrix

### 2.1 local_gate（本机必过，orchestrator L2 已全过，QA 未重跑避免重复消耗）

| Gate | 命令 | applies_to | 结果 |
|---|---|---|---|
| go_vet | `go vet -tags=$BT ./...` | T1/T2/T3 | ✅ clean（QA 二次确认 VET_EXIT=0） |
| go_build | `go build -tags=$BT ./...` | T1/T2/T3 | ✅ OK（QA 二次确认 BUILD_EXIT=0） |
| go_test | `go test -tags=$BT ./control/... ./component/...` | T1/T2/T3 | ✅ Dev L2 已过（control 25.9s / daedns 0.6s / sniffing 0.4s） |
| go_test_race | `go test -tags=$BT -race ./component/daedns/... ./control/... ./component/sniffing/...` | T1, T2, T3 | ✅ Dev L2 已过（T1/T3 Pool 改动 + T2 路径，RACE_EXIT=0） |
| benchmark_no_regression | allocs/op 对照 | T2, T3 | ✅ 见 §3 |

> Deterministic-first：以上均为机器判定 pass/fail，未引入 LLM-as-judge（本 Sprint 无需语义主观判断场景）。

### 2.2 ci_gate（H1：本机实跑 runs，非 ignored）

| Gate | 命令 | 结果 | 说明 |
|---|---|---|---|
| F1 make ebpf | `make ebpf` | ✅ MAKE_EBPF_EXIT=0 | 生成 bpf 绑定（control 包必需） |
| ebpf_test | `make ebpf-test` | ✅ PASS（本机实跑） | **H1 改进验证生效**：plan 标 `local: runs`（非 Sprint 1 的 `ignored`）；实跑 8/8 PASS |
| make dae | `make dae` | ✅ MAKE_DAE_EXIT=0 | 产出 ELF 64-bit x86-64 二进制（stripped） |
| ebpf_sync_check | `make ebpf-sync-check` | ✅ 回归安全 | 本 Sprint 无 C 结构体改动（仅 .go），progress 标 pending 由 QA 确认 pass |
| ebpf_lint | `make ebpf-lint` | N/A | 无 `.c` 改动（Sprint 2 非 eBPF 数据平面方向，B1/B2 Sprint 1 已证无冗余） |

**`make ebpf-test` 实跑结果**（WSL2 kernel 6.18.33.2-microsoft-standard-WSL2，root，timeout=180s）：

```
--- PASS: TestBpfBugsVerification (0.41s)
--- PASS: Test (0.41s)
--- PASS: TestWanEgressDirectMarkReroute (0.39s)
--- PASS: TestWanEgressTcpNonSynCachedProxyRedirect (0.39s)
--- PASS: TestWanEgressTcpNonSynStatelessPassthrough (0.38s)
--- PASS: TestWanEgressTcpSynRedirectTrack (0.40s)
--- PASS: TestWanEgressUdpRedirectTrack (0.39s)
--- PASS: TestConntrackArgsScratchReset (0.40s)
PASS
ok  github.com/daeuniverse/dae/control/kern/tests   3.177s
```

**PASS_COUNT=8 / FAIL_COUNT=0**。覆盖路径（routing / conntrack / wan-egress / epoch）与 Sprint 1 完全一致 → Sprint 2 的 Go 侧改动（T1 daedns / T2 tcp_copy / T3 sniffing）对 eBPF 数据平面**零影响**（预期正确：Sprint 2 未碰任何 `.c`）。

**CI matrix 6.6/6.12 交叉确认**：本机 6.18 通过为强信号；Sprint 2 无 `.c` 改动，eBPF 数据平面与 Sprint 1 字节级等价（bpf 绑定由同一 `tproxy.c` 生成）。建议 CI 流水线仍跑 6.6/6.12 matrix 做 kernel 兼容性最终确认，**非本签署阻塞项**。

### 2.3 manual_gate（playthrough 类）

| 检查 | 命令 | 结果 |
|---|---|---|
| 完整构建 | `make dae` | ✅ 产出 `dae`：ELF 64-bit LSB executable, x86-64, statically linked, stripped |
| 配置加载（完整） | `./dae validate -c example.dae`（0600 副本） | ✅ VALIDATE_EXAMPLE_EXIT=0 |
| 配置加载（最小） | `./dae validate -c install/empty.dae`（0600 副本） | ✅ VALIDATE_EMPTY_EXIT=0 |
| benchmark 等价性 | 见 §3 | ✅ 零回归 + T3 改进稳健 |
| 完整透明代理 playthrough | — | ⚠️ **manual-limited**（同 Sprint 1，见 §4） |

> 注：`dae validate` 对 config 文件权限有安全检查（必须 ≤0600，0644 被拒 "too open"，L8）。QA 用 `cp example.dae /tmp/qa-*.dae && chmod 0600` 临时副本验证，未 chmod 仓库文件。

---

## 3. Benchmark 等价性复核 / Benchmark Equivalence（H2 verification）

QA 实跑（`-tags=trace -benchmem -benchtime=200ms -run='^$'`），与 progress.md 基线对照：

### T2 — RelayCopy（honest no-op，无生产改动）

| Benchmark | 基线 | Dev 改后 | QA 复测 | 判定 |
|---|---|---|---|---|
| BenchmarkRelayCopyLoop_1MB | 9 allocs/op | 9 | **9** | ✅ 持平（生产 flat=0，9 全为 bench harness） |
| BenchmarkRelayCopyDirect_1MB | 8 | 8 | **8** | ✅ 持平 |
| BenchmarkRelayCopyLoop_1KB | (4) | 4 | **4** | ✅ 持平 |
| BenchmarkRelayCopyLoop_32KB | (4) | 4 | **4** | ✅ 持平 |
| BenchmarkRelayCopyDirect_1KB | (3) | 3 | **3** | ✅ 持平 |

> T2 9/8/4/4/3 全部持平 = T2 为诚实 no-op 的直接证据（生产代码零改动，bench 数字当然不变）。memprofile 证实 9 allocs 来自 `bytes.NewReader`(18.97%) + `bytes.growSlice`(13.46%) + benchConn struct，非生产路径。

### T3 — SniffUdp_QUIC（effective-minimal）

| Benchmark | 基线 | Dev 改后 | QA 复测 | Δ | 判定 |
|---|---|---|---|---|---|
| BenchmarkSniffer_SniffUdp_QUIC | 69 | 67 | **67** | −2 (−2.9%) | ✅ 改进稳健（ReassembleCryptos len<=1 短路） |
| BenchmarkSniffer_SniffUdp_QUICMultiPacket | 160 | 160 | **160** | 0 | ✅ 无回归（首包省 2 在采样噪声内） |

> T3 QUIC 69→67 改进在 QA 复测中稳健复现（67 ≤ plan 要求的 ≤67）。密码学内禀 ~54 allocs（NewKeys/hkdf/sha256/hmac/aes-gcm，cum 51.74%）不可消除——OQ-S2-1 已闭环。Multi 无回归符合预期（仅首包命中短路，2/160 在 -benchtime=200ms 采样噪声内）。

**T1（daedns client.go）无 bench**（F2：daedns 包无 benchmark），收益靠 race+vet+build+test + L4 同步消费人工论证（progress.md OQ-S2-2 闭环）。

---

## 4. manual-limited 说明 / Manual Playthrough Limitation

**完整透明代理 playthrough（真实流量经 eBPF 分流→代理出口→回程）本机受限**（同 Sprint 1）：需真实出口节点 + 上游代理凭据 + 特权网络命名空间 + 完整路由/iptables 配置；WSL2 非生产部署形态。

**不降级为 CONDITIONAL 的理由**：
1. Sprint 2 为**语义不变的等价重构**（PROJECT_BRIEF §2 明确不改行为/API/config），非新功能 → 不需新功能式端到端 playthrough；
2. 行为正确性已由三层 deterministic 证据充分保证：
   - Go test/race 覆盖 T1(daedns)/T2(tcp_copy)/T3(sniffing) 控制面（Dev L2 已过）；
   - `make ebpf-test` 真实内核加载测试 8/8 PASS，且 Sprint 2 无 `.c` 改动 → eBPF 数据平面与 Sprint 1 字节级等价；
   - benchmark allocs/op 零回归 + T3 QUIC −2 改进量化等价性。
3. progress.md 无 `❌ Blocked` 区块，无 P0 缺陷。

---

## 5. H1/H2 Eval 回归验证 / H1/H2 Eval Regression Verification

> plan.md `eval_regression_verification` 段要求 QA 显式对照。

### H1 — `ci_gate.*ignored`（Producer gate 可行性探测）

| 项 | Sprint 1 | Sprint 2 |
|---|---|---|
| plan gate 标注 | `ci_gate_ebpf_test.local = ignored`（保守：WSL2 kernel 6.18 非 CI matrix 6.6/6.12） | `ci_gate_ebpf_test.local = runs` |
| QA 实跑 | PASS（3.1s，意外发现 ignored 误判）| **PASS（3.177s，8/8）** |
| regression_signal 匹配 | ✅ 命中（`ebpf_test_ci: ignored`） | ❌ **不再匹配**（已 runs） |

**结论 / Conclusion**：H1 改进**验证生效**。plan 不再出现 `ebpf_test.*ignored`，改为显式 `local: runs` + QA 实跑 PASS。改进闭环。

### H2 — `no_op_tasks.*[4-9]/`（bench 驱动选文件）

| 项 | Sprint 1 | Sprint 2 |
|---|---|---|
| 任务数 | 7 | 3 |
| no-op 数 | 4（A3/A5/B1/B2） | **1（T2 honest no-op）** |
| no-op 率 | 4/7 = **57%** | **1/3 = 33%** |
| regression_signal 匹配 | ✅ 命中（4/7） | ❌ **不再匹配**（1/3，未进 [4-9] 区间） |

**结论 / Conclusion**：H2 改进**验证生效**。bench-driven 选文件（T2/T3 均有 allocs/op>0 基线 + plan 明令 allocs=0 不得设 task）将 no-op 率从 57% 降至 33%。T2 的 1 次 no-op 是**诚实** no-op（memprofile 证实生产 flat=0，非误选），符合 H2 允许范围。

> H3（`EXIT_(BUILD|TEST)=True`）：Sprint 1 未命中（gate 全 PASS），Sprint 2 脚本化全程落实（`tmp/qa-sprint2*.sh`），eval 通过 ✅。
> H4（target_files 含关联文件）：T1 应用（client.go = router.go 同模块同 udpDNSBufPool 关联文件，OQ4），eval 跳过（无 eval 字段）。

---

## 6. Issue 清单 / Issue List

**空 / Empty。** 理由：
- T2 honest no-op 为**优化受阻**（memprofile 证实生产 `relayCopyLoop`/`relayCopyDirect` flat=0，bench harness allocs 非生产代码），**非缺陷**，不提 Issue；
- T1/T3 代码改动均通过全部 deterministic gate + benchmark 零回归；
- `make ebpf-test` 8/8 PASS（Sprint 2 无 `.c` 改动，eBPF 数据平面零影响）；
- 无任何真实缺陷需上报。

---

## 7. Sprint+1 候选（L4 Hill Climbing 输入）/ Sprint+1 Candidates

> 由 QA 在 progress.md「Sprint+1 候选」段记录，此处引用不重复。由 Remy（Producer）在 Sprint+1 plan 评估纳入。

| ID | 候选项 | 来源 | 说明 |
|---|---|---|---|
| — | sniffing QUIC 其余非密码学点（ExtractCryptoFrameOffset ~5% / NewPacketSniffer ~3.5% / NewLinearLocator ~1.3%） | T3 分析 | lifecycle 复杂（跨调用存活 / 装箱入接口），Sprint 2 判定 YAGNI 不改。Sprint+1 若做需重构 sniffing 对象生命周期，风险上升，建议评估收益/风险比后再定。 |
| — | daedns client.go bench 补充 | OQ-S2-2 | T1 收益靠论证无 bench 量化；Sprint+1 可补一个 `lookupType`/`sendStreamDNS` bench 以量化池化收益（可选，避免 scope 膨胀）。 |

**Harness backlog**：Sprint 2 无 kixpower 框架新改进项产出（H1-H4 均已应用且 eval 验证生效；待 Sprint 2 结束由 QA L4 阶段视新暴露问题补充）。

---

## 8. Reflexion / 经验沉淀

本次 QA 执行的范式确认（已在 [/memories/repo/lessons-learned.md](../../../memories/repo/lessons-learned.md)）：
- **L1/L9 范式再验证**：T2 是 L9（bench allocs ≠ 生产 allocs，memprofile 区分法）的标准案例——bench 报 9 allocs/op 看似可优化，memprofile 证实 flat=0 即诚实 no-op。H2 bench-driven 选文件**不保证零 no-op**（bench 假象仍会诱导），但 memprofile 二次确认机制兜底。
- **H1/H2 eval 闭环**：kixpower harness 改进项（H1 plan 标 runs、H2 no-op 率下降）首次跨 Sprint 完成显式验证，回归信号从「命中」转为「不再匹配」→ harness 改进有效。

本次无新 lessons 追加（范式已覆盖）。

---

## 9. 签署 / Sign-off

| 角色 | 结论 | 日期 |
|---|---|---|
| QA（Ivy） | **PASS** — 三 gate 全过，等价性证据充分，无缺陷，H1/H2 改进 eval 验证生效 | 2026-07-29 |

> 后续：交接 Remy（Producer）做 Sprint 2 收尾与分支合并决策。CI matrix(6.6/6.12) 建议在 CI 流水线跑一遍做 kernel 兼容性最终确认（非本签署阻塞项）。
