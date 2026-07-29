---
sprint: 5
sprint_theme: "Tech debt cleanup + measurement precision upgrade (H8 first application) / 技术债清理 + 测量精度升级（H8 首次应用）"
qa_engineer: Ivy
branch: kdae
head_commit: 722b123b
run_at: 2026-07-29
content_language: bilingual
verdict: PASS
verdict_history: "CONDITIONAL (QA first pass) → PASS (orchestrator L2-retry verify, make ebpf-test EXIT=0)"
commits_used: 5   # 3 task code (0e673fe7/1d1021eb/d3e5c4a2) + 1 docs (828afae5) + 1 L2-retry fix (722b123b), within budget 5
open_issue: 0   # ISSUE-1 resolved by L2 retry (restored bpf_bug_verification_test.go, orchestrator 独立复核 make ebpf-test EXIT=0)
issue_tracker: "in-doc (GitHub Issues disabled on fork olicesx/dae; tracked in §7 below)"
---

# Sprint 5 QA Sign-off — 技术债清理 + 测量精度升级（H8 首次应用）

> QA: Ivy. Method: deterministic-first（gate 优先机器判定），LLM-as-judge 不用于 deterministic 已覆盖项。本 Sprint 是测试瘦身 + CPU 算法 + H8 bench harness 首次应用。
>
> **verdict = PASS（升级自 CONDITIONAL）**：local_gate 全过 + manual_gate 全过 + ci_gate 全过。ISSUE-1（T1 误删 Makefile 引用的 `control/bpf_bug_verification_test.go`）经 L2 retry 修复（commit 722b123b 恢复文件），orchestrator 独立复核 `make ebpf-test` EXIT=0（`ok github.com/daeuniverse/dae/control/kern/tests 3.245s`）。升级判据满足「local+ci+manual 全过」。详见 §2.2 + §7。

## §1 任务交付复核 / Task Delivery Review

| Task | target_files | commits | status |
|------|-------------|---------|--------|
| T1 AI 批量测试瘦身（删 108 / 留 90 + 恢复 3 helper + 3 bulk-infra） | 108 deleted + 3 new helpers + edits to existing helpers | 0e673fe7 | ⚠️ delivered（引入 1 回归，见 §7） |
| T2 sniffHTTPHostHeader CPU 热路径优化 | component/sniffing/http.go | 1d1021eb | ✅ delivered |
| T3 H8 bench harness deadline 化 | component/sniffing/benchmark_test.go | d3e5c4a2 | ✅ delivered |

**Fidelity（源码改动 gated 审查）**：T2 改动仅 `component/sniffing/http.go`（+45/-10，target 完全匹配）；T3 改动仅 `component/sniffing/benchmark_test.go`（+43/-3，target 完全匹配）；T1 删除 108 文件全在批量 commit 范围内（comm -12 验证，§3.1）。**0% ungated**（源码 target_files 100% 匹配 plan），延续 Sprint 1-4 记录。

**commits_used = 4/5**（3 task code + 1 docs），bug_reserve=1 未用（T1 helper 链恢复未额外耗 commit，但 T1 引入的回归需 Sprint+1 修复）。

## §2 Gate 执行矩阵 / Gate Execution Matrix

### 2.1 local_gate（orchestrator-L2 已复核，QA 不重跑；go test ./... QA 独立复核）

| Gate | cmd | result | source |
|------|-----|--------|--------|
| go_vet | `go vet -tags=trace ./...` | ✅ PASS | orchestrator-L2 (EXIT=0) |
| go_build | `go build -tags=trace ./...` | ✅ PASS | orchestrator-L2 (EXIT=0) |
| go_test | `go test -tags=trace ./...` | ✅ PASS | orchestrator-L2 + QA 独立复核（19 包 ok / 0 FAIL，§3.3） |
| go_test_race | `go test -race -tags=trace ./component/sniffing/... ./control/...` | ✅ PASS (无 DATA RACE) | orchestrator-L2 |

### 2.2 ci_gate（QA 独立补跑）

| Gate | cmd | result | evidence |
|------|-----|--------|----------|
| **ci_gate_ebpf_test** | `make ebpf-test` | ❌ **FAIL (EXIT=2)** | `stat /root/dae/control/bpf_bug_verification_test.go: directory not found`；T1 删除了 Makefile 行 136/151/166/181 引用的文件。详见 §7 |
| ci_gate_make_ebpf | `make ebpf` | ✅ PASS | EXIT=0（eBPF 程序编译正常） |
| ebpf_sync_check | `make ebpf-sync-check` | ✅ PASS | EXIT=0（`git diff --exit-code` clean，无 C 结构体改动） |
| ebpf_lint | `make ebpf-lint` | N/A | 无 .c 改动 |

### 2.3 manual_gate（QA 独立复核）

| Gate | result | evidence |
|------|--------|----------|
| make_dae | ✅ PASS | EXIT=0；`go build -tags=trace -o dae`，二进制正常产出 |
| dae_validate_example | ✅ PASS | `./dae validate -c example.dae` EXIT=0（L8：chmod 0600 临时副本 /tmp/qa-s5-example.dae） |
| dae_validate_empty | ✅ PASS（正确拒绝） | `./dae validate -c /dev/null` EXIT=1「section global is required but not provided」— 空配置被正确判定无效 |

### 2.4 决定性 gate（QA 独立跑，详见 §3/§4/§5）

| Gate | result | 备注 |
|------|--------|------|
| deletion_protection_check (T1) | ✅ PASS | 108 删除全在批量 commit，原生零触碰（§3.1） |
| test_src_ratio (T1) | ✅ PASS | 1.03→0.490（target ~0.5，§3.2） |
| cpu_profile_review (T2 H7) | ✅ PASS | bytes.Index cum 8.72%（复现 Dev 8.66%，±1pp 噪声，§4） |
| memprofile_review (T2 H5) | ✅ PASS | Extended 1 alloc（Host string inherent）/ NoHost 0 alloc（§4） |
| h8_deadline_sync_verification (T3 H8) | ✅ PASS | readStreamOnceWithReadDeadline 出现 / readStreamOnceAsync 零出现（§5） |

## §3 T1 测试瘦身独立复核 / T1 Test Pruning Independent Review

### 3.1 deletion_protection（决定性）

| 检查项 | Dev 报告 | QA 实测 | 一致？ |
|--------|---------|---------|--------|
| T1 删除文件数 | 108 | 108 | ✅ |
| 删除文件 ∩ 批量 commit 新增 | 全部 | 108/108（comm -12 交集=108） | ✅ |
| 删除文件中非批量来源 | — | 0（NOT_IN_BULK=0） | ✅ |
| 原生 16 个被误删 | 0 | 0 | ✅ |

**False-positive 排查（诚实披露）**：QA 初查时 grep pattern `cipher|config_parser` 命中 2 个删除文件（`cipher_bench_test.go` / `error_test.go`），疑为原生误删。精准确认后：这 2 个是批量 commit #970 加的 **bench/error 测试**（属删除目标），非原生。真正的原生 `cipher_test.go` / `config_parser_test.go` 仍存在。✅

**plan.md 文档发现（非阻塞）**：plan.md T1 KEEP 原生清单列了 `component/sniffing/{quic_bench,sniffing_bench}`，但这两个文件**已被批量 commit #970 在 Sprint 5 之前删除**（git log diff-filter=D 证实 #970 删除它们）。T1 未触碰（git show 0e673fe7 证实）。这是 plan.md 的陈旧条目（文件早已不存在），非 T1 缺陷。恢复这 2 个原生 bench 文件可作为 Sprint+1 候选（§8）。

### 3.2 test:src 比率

| 指标 | baseline | after | target | 状态 |
|------|----------|-------|--------|------|
| test 文件数 | 203 | 98 | — | ✅ |
| src 文件数 | ~197 | 200 | — | — |
| test:src | 1.03 | **0.490** | ~0.5 | ✅ 达标 |

### 3.3 保留文件确认 + go test ./... 独立复核

| 类别 | 期望 | QA 实测 | 状态 |
|------|------|---------|------|
| helpers (test_helpers_test.go) | 9 原生 + 3 新增 = 12 | 12（9 原生 + 3 集中恢复） | ✅ |
| fuzz (_fuzz_test.go) | 6 | 6（http/quic/tls/cipher/dns_cache/runtime_supervisor） | ✅ |
| T3 target benchmark_test.go | 存在 | 存在 | ✅ |
| 3 新集中 helper 文件 | scripted_packet_conn/test_fixtures/dns_message | 全在（168/182/123 行） | ✅ |
| 3 恢复 bulk-infra 文件 | udp_quic_initial_regression/udp_reuse_simulation/udp_sniffer_loss | 全在（578/626/327 行） | ✅ |
| go test ./... | clean | 19 包 ok / 0 FAIL / EXIT=0 | ✅ |

## §4 T2 H7 cpu_profile 决定性复核 / T2 CPU Profile Decisive Review

QA 独立跑 `BenchmarkSniffHTTPHostHeader` -cpuprofile（单包 ./component/sniffing/，benchtime=3s）。

### 4.1 bench 数字（QA vs Dev）

| Benchmark | QA ns/op | Dev ns/op | QA allocs | Dev allocs | 一致？ |
|-----------|----------|-----------|-----------|------------|--------|
| Extended | 89.17 | 80.91 | 1 | 1 | ns +10%（微基准噪声）/ allocs ✅ |
| NoHost | 37.30 | 32.82 | 0 | 0 | ns +13.6%（微基准噪声）/ allocs ✅ |

> ns/op QA 略高于 Dev（WSL2 系统负载差异），属正常微基准波动。allocs 精确一致（决定性）。Dev 声称的 -36%/-43% 改善 vs pre-T2 baseline 无法直接复核（无 baseline 环境），但绝对值在同一量级。

### 4.2 CPU profile cum%（H7 决定性维度）

| 函数 | baseline cum% | Dev after | QA after | 判据 |
|------|--------------|-----------|----------|------|
| **bytes.Index** | 57.92% | 8.66% | **8.72%** | ✅ ±1pp 噪声内复现（H7 核心） |
| bytes.IndexByte（新优化路径） | — | — | 34.75% | ✅ IndexByte 替代 2 字节 Index，走 indexbytebody 汇编（28.15% flat） |
| sniffHTTPHostHeader | 16.85%(S4) | — | 95.64% | ⚠️ L14 微基准陷阱（被测函数=唯一工作，cum% 必然接近 100%，非回归） |
| gcBgMarkWorker | — | — | 2.12% | ✅ 极低，确认 CPU 算法任务非 alloc 驱动 |
| mallocgc | — | — | 9.54% | ✅ 低（1 alloc/op inherent string） |

**H7 verdict：PASS。** bytes.Index cum 8.72% 决定性复现 Dev 的 8.66%（±1pp）。IndexByte 优化路径可见。GC 极低（2.12%）确认这是 CPU 算法优化非 alloc 驱动。sniffHTTPHostHeader 自身 cum 95.64% 是 L14 微基准陷阱（OQ-S5-1 已闭环：该函数是 bench 唯一工作，cum% 必然高；真实收益看 bytes.Index cum 大降 + ns/op 绝对下降）。

### 4.3 memprofile（H5 旁证）

| 路径 | allocs/op | flat 分析 | 状态 |
|------|-----------|----------|------|
| Extended（含 Host） | 1（32 B） | Host string 返回 inherent（无 API 改动不可消） | ✅ |
| NoHost（无 Host） | 0 | 零分配 | ✅ |

**H5 verdict：PASS。** 剩余 1 alloc = Host string 返回的 inherent 代价（API 契约），NoHost 路径零分配。与 Dev 报告完全一致。

## §5 T3 H8 deadline 路径决定性复核 / T3 H8 Deadline Path Decisive Review

### 5.1 h8_deadline_sync gate

| 检查 | Dev | QA | 状态 |
|------|-----|-----|------|
| grep -c 'SetReadDeadline\|net.Pipe\|deadlineConn' | 5 | 16（含注释 + struct 方法） | ✅ >>3 |
| deadlineConn 定义 | 包装 bytes.Reader + no-op SetReadDeadline | 确认（benchmark_test.go:28-46） | ✅ |

### 5.2 pprof deadline-sync 路径确认（决定性）

| 函数 | top100 出现 | cum% | 期望 | 状态 |
|------|------------|------|------|------|
| readStreamOnceWithReadDeadline | ✅ 1 次 | 7.89% | 应出现（deadline-sync 激活） | ✅ |
| readStreamOnceAsync | ❌ 0 次 | — | 应不出现（async 消除） | ✅ |

pprof `-list` 证实 `readStreamOnceWithReadDeadline` 实际执行 `s.conn.SetReadDeadline(s.deadline)` @sniffer.go:170（非空壳）。deadlineConn 的 no-op SetReadDeadline 成功让 sniffer 走 deadline-sync 分支而非强制 async。

### 5.3 playthrough（bench 断言 = 语义不变）

| Benchmark | QA allocs | Dev allocs | 原 async | 断言 | 状态 |
|-----------|-----------|------------|----------|------|------|
| SniffTcp_HTTP | 5 (224 B) | 5 | ~12 | PASS | ✅ |
| SniffTcp_TLS | 6 (240 B) | 6 | ~12 | PASS | ✅ |
| SniffTcp_NotApplicable | 3 (168 B) | 3 | ~12 | PASS | ✅ |

**H8 verdict：PASS。** 3 bench 断言全过（语义不变）；allocs 5/6/3 与 Dev 完全一致，趋近 deadline-sync 基线（S4 done.md deadline_sync_read=5）。async 路径消除（pprof readStreamOnceAsync 零出现）。OQ-S5-3 选型（自定义 deadlineConn）成功。

## §6 H1/H3/H5/H7/H8 eval 回归验证 / Eval Regression Verification

| Eval | regression_signal | 命中？ | 处置 |
|------|-------------------|--------|------|
| H1 | `ci_gate.*ignored` | ❌ 未命中（ebpf-test 实跑，但 FAIL 见 §7；make ebpf 实跑 EXIT=0） | ⚠️ H1 部分受影响（ebpf-test 非 ignored 但断裂） |
| H3 | `EXIT=FAIL` | ⚠️ 部分命中（ci_gate_ebpf_test EXIT=2） | 见 §7 |
| H5 | harness allocs flat=0 / 目标 flat 未降 | ❌ 未命中（memprofile Extended 1 alloc inherent / NoHost 0） | ✅ H5 持续 |
| H7 | cpu flat no improvement / GC not dominant | ❌ 未命中（bytes.Index cum -49pp；GC 2.12% 低） | ✅ H7 持续 |
| H8（首次应用） | deadline-sync 路径未激活 | ❌ 未命中（readStreamOnceWithReadDeadline 出现 / async 消除） | ✅ H8 首次应用即验证价值 |

**结论**：H5/H7/H8 eval 全通过。H1/H3 受 ci_gate_ebpf_test 回归影响（非 eval 本身失效，是 T1 引入的独立缺陷）。

## §7 Issue 清单 / Issue List

### ISSUE-1（真实缺陷，P1）：T1 误删 Makefile 引用的 `bpf_bug_verification_test.go`，`make ebpf-test` 断裂

- **严重级别**：P1（CI gate 断裂，但 `make dae`/`make ebpf`/二进制正常，不影响运行时）
- **根因**：T1 删除分类只查「是否批量 commit 加的」（deletion_protection gate 通过），未查「是否被 Makefile/CI 构建系统引用」。`control/bpf_bug_verification_test.go` 是批量 commit #970 加的（deletion_protection 视角合法删除），但同时是 Makefile `ebpf-test` target 的 `go generate` 依赖（行 136/151/166/181）。`go vet`/`go test ./...` 抓不到（build tag `//go:build linux && dae_bpf_tests` 默认不可见 + Makefile `go generate` 不在 test 流程）。
- **复现**：`make ebpf-test` → `stat /root/dae/control/bpf_bug_verification_test.go: directory not found` → EXIT=2
- **回归确认**：T1 parent（e11c0aa8）文件存在 + Makefile 4 处引用 → `make ebpf-test` 正常；T1（0e673fe7）删文件后 → 断裂。确认为 T1 引入的回归。
- **影响**：CI 的 eBPF kernel 测试（`go test -tags dae_bpf_tests ./control/kern/tests/...`）无法执行 generate 前置步骤。实际 eBPF 程序编译正常（`make ebpf` EXIT=0）。
- **建议修复**（Dev 执行）：二选一 —— ① 从 git 历史恢复 `control/bpf_bug_verification_test.go`（`git checkout 0e673fe7^ -- control/bpf_bug_verification_test.go`）；② 若该文件确为冗余，同步删除 Makefile 行 136/151/166/181 的 4 处 `go generate ./control/bpf_bug_verification_test.go && \` 引用。
- **Lesson 候选（L16）**：deletion_protection 必须额外扫描 Makefile/CI 引用，不能只查 Go import 依赖。build-tag 门控文件（dae_bpf_tests）对 `go vet`/`go test ./...` 不可见，但被 Makefile `go generate` 引用 → 只有 `make ebpf-test` 能抓到断裂。

## §8 Sprint+1 候选（L4 输入）/ Sprint+1 Candidates

| 候选 | 来源 | 方向 | 优先级 |
|------|------|------|--------|
| 修复 ISSUE-1（恢复 bpf_bug_verification_test.go 或清 Makefile 引用） | §7 本 Sprint 回归 | 缺陷修复 | P1（阻塞 ci_gate PASS） |
| 恢复原生 quic_bench_test.go / sniffing_bench_test.go | §3.1 plan.md 陈旧条目 | 测试基线恢复 | P3（被 #970 删除的原生 bench，git 历史可恢复） |
| deletion_protection gate 增强（扫描 Makefile/CI 引用） | §7 L16 | 流程改进 | P2（防同类回归） |

## §9 Reflexion 经验沉淀 / Reflexion

**新增 L16 候选（已写入 /memories/repo/lessons-learned.md）**：deletion_protection 的盲区 —— Makefile/CI 构建系统引用。

- **Symptom**：T1 删除 `bpf_bug_verification_test.go` 通过了 deletion_protection（文件是批量 commit 加的）+ go vet + go test ./...（build tag `dae_bpf_tests` 默认不可见），但 Makefile `ebpf-test` target 的 `go generate` 引用它 → `make ebpf-test` 断裂。
- **Rule**：测试瘦身的 deletion_protection 不能只查 Go import 依赖 + 原生保护，必须额外扫描构建系统（Makefile/.github/workflows/CI 脚本）对测试文件的引用。build-tag 门控的测试文件（`dae_bpf_tests` / `integration` 等）对默认 `go test` 不可见，但常被 Makefile `go generate` / CI step 引用。
- **检测方法**：删除前对每个候选执行 `grep -rn "<filename>" Makefile/ .github/ 2>/dev/null`，有命中则保留或同步更新构建脚本。
- **范式扩展**：L15（helper 链 = Go import 依赖）→ L16（构建系统依赖）。两者都是「删除决策的隐藏依赖」，只是依赖载体不同（Go 符号 vs Makefile 目标）。

---

## Verdict: **CONDITIONAL**

| 维度 | local_gate | ci_gate | manual_gate | 结论 |
|------|-----------|---------|-------------|------|
| 结果 | ✅ 全过（orchestrator-L2 + QA go test 复核） | ⚠️ 1 FAIL（ci_gate_ebpf_test）/ 2 PASS | ✅ 全过（QA 独立） | **CONDITIONAL** |

依据签署规则：local_gate 全过 + manual_gate 全过 + ci_gate 有 1 个真实缺陷（ci_gate_ebpf_test FAIL）= **CONDITIONAL**。非 FAIL（local+manual 全过、二进制正常产出、回归不影响运行时）、非 PASS（ci_gate 有真实回归未修）。

**CONDITIONAL 解除条件**：Dev 修复 ISSUE-1（恢复 `bpf_bug_verification_test.go` 或清 Makefile 4 处引用）→ QA 复跑 `make ebpf-test` EXIT=0 → 升级为 **PASS**。

**T2/T3 决定性 gate 独立复现结论**：与 Dev 报告一致（bytes.Index cum 8.72% vs Dev 8.66% ±1pp；allocs HTTP 5/TLS 6/NotApplicable 3 精确一致；readStreamOnceWithReadDeadline 出现 + async 消除）。T1 测试瘦身目标达成（test:src 1.03→0.490），仅遗留 1 个 Makefile 依赖回归。

> Manual playthrough 说明：本 Sprint 是测试瘦身 + CPU 算法 + harness 改进（非新功能），行为正确性由 deterministic gate（go test 19 包 / race / bench 断言全过）+ pprof 路径确认保证。透明代理完整 playthrough 同 Sprint 1-4 manual-limited（WSL2 非生产部署）。
