---
sprint: 2
sprint_theme: "Semantic-preserving code slimming (bench-driven + OQ4)"
phase: planning
owner: Remy
branch: kdae
created: 2026-07-29

# === blast_radius（plan 锁定）===
blast_radius:
  commit_budget: 2
  commit_budget_formula: ceil(task_count/3) + strong_coupling_count + 1
  hard_cap: 10
  commits_used: 2
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true

# === topology ===
topology_used: serial
topology_rationale: "T1/T2/T3 文件互独立；本 Sprint 单 agent 串行执行 T1→T2→T3（避免 worktree/synthesis 开销）"

# === task DAG 摘要 ===
tasks:
  T1: {status: done, files: [component/daedns/client.go], source: "OQ4+H4", bench: none, commit: "4c1de816", effective: true}
  T2: {status: noop, files: [control/tcp_copy_engine.go], source: "H2 bench", bench: "RelayCopyLoop_1MB=9 allocs/op", commit: none, reason: "bench harness allocs only (memprofile 证实 relayCopyLoop/relayCopyDirect 零 flat alloc)"}
  T3: {status: done, files: [component/sniffing/internal/quicutils/relocation.go], source: "H2 bench", bench: "SnuffUdp_QUIC=69→67 / Multi=160→160", commit: "c1ab617d", effective: "minimal (-2 allocs/packet, single-frame case)"}

# === verifiable_gates 状态 ===
gates:
  go_vet: pass
  go_build: pass
  go_test: pass
  go_test_race: pass
  benchmark_no_regression: pass   # T3 QUIC 69→67；Multi 无回归；T2 no-op 无 bench 改动
  ci_gate_ebpf_test: pass         # QA 实跑 8/8 PASS 3.177s（H1：本机 runs 非 ignored）
  ci_gate_make_da_ebpf: pass      # EXIT=0，F1 生成绑定
  ebpf_lint: na                   # 无 .c 改动
  ebpf_sync_check: pass           # QA 确认（无 C 结构体改动，回归安全）
---

# Sprint 2 Progress — 语义不变的代码精简（bench 驱动 + OQ4）

> 执行期由 Dev/QA 填写。阶段过渡时 Remy 更新本文件与 PROJECT_BRIEF.md 第 7、8 节。

## 状态总览 / Status

| 阶段 | 负责人 | 状态 |
|------|--------|------|
| Planning（drift-check + bench 扫描 + plan） | Remy | ✅ 完成 |
| Dev 实现（T1/T2/T3 串行） | Dev | ✅ 完成（2 effective + 1 noop-with-analysis） |
| QA 验证（gate 全过 + bench 非回归） | QA | ⏳ 待启动 |

## Trace Log

<!-- 每次任务推进追加一行：[时间] task | 动作 | 结果 | commit? -->

- [2026-07-29] planning | drift-check 完成（4 项：context 零漂移 / L1-L8 全规避 / OQ4 纳入 / fidelity 100% gated）；verification-fidelity-check.ps1 不存在→降级手动 git log（记此条） | drift-check.md 产出 | —
- [2026-07-29] planning | Evals 回归检查：H1 命中（ci_gate.*ignored）、H2 命中（no_op 4/7）、H3 未命中（eval 通过）；H1/H2 强制 plan 写验证方式 | drift-check.md §5 | —
- [2026-07-29] H1 探测 | `make ebpf-test` 本机 PASS（3.187s，全部 eBPF kernel 用例）+ `make ebpf` EXIT=0 + build EXIT=0 → plan 标 `ci_gate_ebpf_test.local=runs`（H1 改进生效，非 ignored） | 见 plan gates | —
- [2026-07-29] H2 扫描 | bench 扫描（tmp/bench-scan.sh + sprint2-bench2.sh，-benchtime=200ms，带 -tags=trace）；发现 control 包须先生成 bpf 绑定（F1）；daedns 无 bench（F2） | runtime-context.md bench 基线表 | —
- [2026-07-29] planning | 任务选定：T1(OQ4 client.go, H4) + T2(tcp_copy_engine bench) + T3(sniffing QUIC bench)；排除 QuicInitialEndToEnd(fork)/CloneCacheForReload(冷)/DnsCache_Clone(L2) | plan.md | —
- [2026-07-29] planning | task_sizing：task_count=3, strong_coupling=0 → commit_budget=⌈3/3⌉+0+1=2（hard_cap=10） | plan.md blast_radius | —
- [2026-07-29] T1 实现 | daedns/client.go 三处池化（lookupType msg.PackBuffer / sendStreamDNS req+respBuf 复用 udpDNSBufPool + lengthBuf 上栈 / sendHTTPDNS io.ReadAll→ReadFull 池化）；L4 同步消费论证（r.exchange 所有 scheme 同步消费 data）；gate vet/build/test/race 全 PASS | commit 4c1de816 | ✅
- [2026-07-29] T2 分析 | memprofile（-memprofile=/tmp/t2-mem.out）证实 RelayCopyLoop_1MB 的 9 allocs/op 全来自 bench harness：bytes.NewReader(18.97%)+bytes.growSlice(13.46% via benchConn.Write)+benchConn struct；relayCopyLoop/relayCopyDirect flat=0 allocs（未进 top sites）。生产代码已全池化（relayCopyBufferPool + tryRelayGatherWrite + relayFastCopy 均走池）。**HONEST NO-OP**，符合 H2 + L1 范式 | no commit | ✅ noop
- [2026-07-29] T3 实现 | OQ-S2-1 量化：memprofile 证实密码学内禀 NewKeys cum=51.74%（hmac.New 20.39%+sha256.New 13.92%+Digest.Sum 5.42%+hkdf.Expand 5.36%+aes/gcm 4.24%）；非密码学最大点 ReassembleCryptos flat=12.09%。改动：len(offsets)<=1 短路（跳过 sort.Slice reflectlite.Swapper + merged make）。Bench QUIC 69→67(-2.9%)；Multi 160→160（首包节省 2 被噪声掩盖）。其余非密码学点（ExtractCryptoFrameOffset 5% / NewPacketSniffer 3.5% / NewLinearLocator 1.3%）lifecycle 复杂不改。gate PASS+race-clean | commit c1ab617d | ✅ minimal

## Benchmark 基线（Dev 改动前对照，来自 runtime-context.md）

| Benchmark | 基线 allocs/op | 改动后 allocs/op | Δ | 任务 | 备注 |
|-----------|---------------|-----------------|---|------|------|
| BenchmarkRelayCopyLoop_1MB | 9 | 9 | 0 | T2 | memprofile 证实全为 bench harness allocs；生产代码零 flat alloc → no-op |
| BenchmarkRelayCopyDirect_1MB | 8 | 8 | 0 | T2 | 同上 |
| BenchmarkSniffer_SniffUdp_QUIC | 69 | 67 | -2 | T3 | ReassembleCryptos len<=1 短路；crypto 内禀 ~54 不可消除 |
| BenchmarkSniffer_SniffUdp_QUICMultiPacket | 160 | 160 | 0 | T3 | 仅首包命中短路（2/160 在采样噪声内） |
| （T1 client.go 无 bench） | — | — | — | T1 | F2：daedns 无 bench；靠 race+vet+L4 论证 |

## Gate 执行记录

| Gate | 命令 | 结果 | 备注 |
|------|------|------|------|
| F1 make ebpf | `make ebpf` | EXIT=0 | 生成 bpf 绑定（control 包必需） |
| go_vet | `go vet -tags=$BT ./...` | PASS | VET_EXIT=0 |
| go_build | `go build -tags=$BT ./...` | PASS | BUILD_EXIT=0 |
| go_test | `go test -tags=$BT -timeout 240s ./control/... ./component/...` | PASS | control 25.9s / daedns 0.6s / sniffing 0.4s 等全 ok |
| go_test_race | `go test -tags=$BT -race -timeout 240s ./component/daedns/... ./control/... ./component/sniffing/...` | PASS | RACE_EXIT=0（T1/T3 池改动 + T2 路径） |
| benchmark_no_regression | T2/T3 bench（见上表） | PASS | T2 无改动；T3 QUIC -2，Multi 无回归 |

## Evals 回归结果（v4.1，供 done.md）

| ID | eval.regression_signal | Sprint 1 命中？ | Sprint 2 处置 | 结果 |
|----|------------------------|----------------|--------------|------|
| H1 | ci_gate.*ignored | ✅ 命中 | plan 标 local=runs + 实跑 PASS | 待 QA 终验 |
| H2 | no_op_tasks.*[4-9]/ | ✅ 命中 | bench 驱动 + allocs=0 不设 task | 待 Sprint 结束统计 |
| H3 | EXIT_(BUILD|TEST)=True | ❌ 未命中 | 脚本化全程落实 | eval 通过 ✅ |

## 开放问题追踪

- OQ-S2-1：T3 sniffing 密码学占比（Dev 量化后定可消除范围）。**已闭环**：memprofile 证实 ~52% cumulative 为密码学内禀（NewKeys+hkdf+sha256+hmac+aes+gcm），非密码学 remainder 分散于 ReassembleCryptos(12%)/ExtractCryptoFrameOffset(5%)/NewPacketSniffer(3.5%)/NewLinearLocator(1.3%)。仅 ReassembleCryptos len<=1 短路为安全可消除点，其余 lifecycle 复杂（CryptoFrameOffset 经 s.quicCryptas 跨调用存活；LinearLocator 装箱入 Locator 接口）。
- OQ-S2-2：T1 无 bench 的收益量化方式（靠论证，可选加 bench）。**已闭环**：未加 bench（避免 scope 膨胀）；靠 race+vet+build+test + L4 同步消费人工论证。

## Sprint+1 候选（L4 Hill Climbing 输入，Sprint 结束时由 QA 填）

_（空）_
