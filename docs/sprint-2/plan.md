---
sprint: 2
sprint_theme: "Semantic-preserving code slimming (bench-driven + OQ4) / 语义不变的代码精简（bench 驱动 + OQ4）"
phase: planning
owner: Remy
branch: kdae
created: 2026-07-29
content_language: bilingual
prev_sprint: 1
drift_check: docs/sprint-2/drift-check.md

# === blast_radius（plan 锁定，执行期不得超）===
blast_radius:
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true
  hard_cap: 10
  commit_budget: 2
  commit_budget_formula: ceil(task_count/3) + strong_coupling_count + 1
  commit_budget_derivation: "ceil(3/3) + 0 + 1 = 2（task_count=3, strong_coupling=0；T1/T2/T3 文件互独立全并行）"
  commit_budget_risk_note: >
    公式 ⌈n/3⌉ 内含期望 no-op 率。H2 降低 no-op 后若 3 任务全有效（需 3 commit），
    可在 hard_cap=10 内走文档化解锁（记 progress.md）。预期 T3（sniffing）有密码学内禀 no-op 风险，
    故预期有效≈2，与 budget=2 吻合。

# === task_sizing ===
task_sizing:
  task_count: 3
  strong_coupling_count: 0
  dag_layers: 1
  topology: parallel
  topology_rationale: "T1(daedns/client.go) / T2(control/tcp_copy_engine.go) / T3(component/sniffing/*) 文件与模块互独立，零编辑冲突 → 全并行。"

# === task DAG ===
tasks:
  T1:
    name: "daedns client.go per-query buffer 池化（OQ4）"
    source: "Sprint 1 OQ4 + H4"
    target_files: ["component/daedns/client.go"]
    target_sites:
      - "sendStreamDNS: req/lengthBuf/respBuf @556-571"
      - "queryHTTPS: io.ReadAll @542"
      - "lookupType: msg.Pack → msg.PackBuffer @253"
    depends_on: []
    bench_coverage: none
    pool_reuse: "udpDNSBufPool（client.go:39，同模块既有池）"
    safety_condition: "L4：PackBuffer 返回 data 须同步消费；lengthBuf 上栈 [2]byte"
    expected: effective
  T2:
    name: "tcp relay copy 路径未池化分配消除"
    source: "H2 bench-driven"
    target_files: ["control/tcp_copy_engine.go"]
    target_sites:
      - "BenchmarkRelayCopyLoop_1MB (9 allocs/op) / RelayCopyDirect_1MB (8) / 32KB (4) / 1KB (4)"
    depends_on: []
    bench_coverage: yes
    bench_baseline: {RelayCopyLoop_1MB: "9 allocs/op", RelayCopyDirect_1MB: "8 allocs/op"}
    pool_reuse: "relayCopyBufferPool（tcp_copy_engine.go:18，已存在 → 定位未走池的分配）"
    expected: effective
  T3:
    name: "sniffing QUIC 嗅探非密码学分配消除"
    source: "H2 bench-driven"
    target_files: ["component/sniffing/*.go"]
    target_sites:
      - "BenchmarkSniffer_SniffUdp_QUIC (69 allocs/op) / SniffUdp_QUICMultiPacket (160)"
    depends_on: []
    bench_coverage: yes
    bench_baseline: {SnuffUdp_QUIC: "69 allocs/op", SnuffUdp_QUICMultiPacket: "160 allocs/op"}
    pool_reuse: "无既有 Pool；Dev 须隔离非密码学分配（Keys/NewKeys 为密码学内禀→排除）"
    expected: effective_or_noop
    noop_risk: "QUIC 嗅探含密码学（PayloadDecrypt/NewKeys）；若 allocs 全来自密码学→诚实 no-op（H2 允许，须有分析论证）"

# === verifiable_gates ===
gates:
  go_vet:        {cmd: "go vet -tags=$(cat .build_tags) ./...", target: clean}
  go_build:      {cmd: "go build -tags=$(cat .build_tags) ./...", target: ok}
  go_test:       {cmd: "go test -tags=$(cat .build_tags) ./control/... ./component/...", target: pass}
  go_test_race:  {cmd: "go test -tags=$(cat .build_tags) -race ./component/daedns/... ./control/... ./component/sniffing/...", target: pass, reason: "T1/T2/T3 涉及 Pool/buffer 改动，D1 race 必跑"}
  benchmark_no_regression:
    cmd: "go test -tags=$(cat .build_tags) -bench=. -benchmem -run='^$' -benchtime=200ms ./control/... ./component/..."
    target: "allocs/op 不增；T2/T3 有效则须下降"
    h2_verification: "每任务记录 bench 前后值；allocs/op=0 的热点不得设 task（H2 硬约束，本 plan 已过滤）"
  ci_gate_ebpf_test:
    cmd: "make ebpf-test"
    local: runs          # ← H1 应用：Sprint 1 标 ignored，Sprint 2 改 runs（本机 PASS 3.187s）
    h1_verification: "Sprint 1 = ignored（过保守）；Sprint 2 实跑 PASS → 标 runs。验证 H1 改进生效：plan 不再出现 `ebpf_test.*ignored`"
  ci_gate_make_da_ebpf:
    cmd: "make ebpf"
    local: runs          # EXIT=0，生成 bpf 绑定
  ebpf_lint:     {cmd: "make ebpf-lint", target: "0 warning（本 Sprint 无 .c 改动，仅回归安全，可选）"}
  ebpf_sync_check: {cmd: "make ebpf-sync-check", target: pass, note: "本 Sprint 无 C 结构体改动，回归安全"}
  no_behavior_change: {target: "config 语言/CLI/错误码/API 不变（语义保持）"}

# === H1/H2 eval 回归验证（drift-check §5 要求显式写出）===
eval_regression_verification:
  H1: "本机实跑 make ebpf-test = PASS（3.187s，全部 eBPF kernel 用例）；plan.gates.ci_gate_ebpf_test.local = runs（非 ignored）。与 Sprint 1 progress 的 `ebpf_test_ci: ignored` 形成对照 → H1 改进可验证生效。"
  H2: "bench-driven：T2/T3 均有 allocs/op>0 的 bench 基线（见 task_sizing）；plan 明令 allocs/op=0 热点不得设 task。Sprint 结束统计 no-op 率，目标 < Sprint 1 的 57%（4/7）。与 Sprint 1 `no_op_tasks: 4/7` 形成对照 → H2 改进可验证生效。"
---

# Sprint 2 Plan — 语义不变的代码精简（bench 驱动 + OQ4）

> 延续 Sprint 1 方向。**核心区别 = 应用 H2（bench 驱动选文件）**，降低 Sprint 1 的 57% no-op 率。
> 输入：[drift-check.md](drift-check.md) + [runtime-context.md](runtime-context.md) + Sprint 1 产出。

## 1. 目标 / Goals

- **T1（OQ4，用户指定）**：daedns `client.go` per-query buffer 池化（sendStreamDNS/queryHTTPS/lookupType），复用 udpDNSBufPool。
- **T2（H2 bench 驱动）**：tcp relay copy 路径未池化分配消除（relayCopyBufferPool 已存在，定位漏网分配）。
- **T3（H2 bench 驱动）**：sniffing QUIC 嗅探非密码学分配消除（隔离密码学内禀部分）。
- **整体**：所有改动**语义保持**（不改行为/API/config），通过完整 gate。

## 2. 非目标 / Out-of-Scope（本 Sprint 不做什么）

- ❌ 锁合并 / 重排（lock consolidation/reordering）— Sprint+3 候选
- ❌ 巨型文件拆分（client.go / tcp_copy_engine.go 物理拆分）
- ❌ 测试瘦身 / 批量删测试
- ❌ 行为/API/config 变更、新 feature gate、新协议
- ❌ 不碰 vendor / vmlinux-*.h / fork 依赖（quic-go、outbound）
- ❌ eBPF C（tproxy.c）改动 — Sprint 1 B1/B2 已证无真冗余，本 Sprint 不再扫
- ❌ 冷路径优化（CloneCacheForReload，Sprint 1 先例不强求）
- ❌ test-only 函数优化（DnsCache_Clone/FillInto*，L2 YAGNI）

## 3. 任务 DAG / Task DAG

```
T1 (daedns/client.go)   ─┐
T2 (tcp_copy_engine.go) ─┼── 全并行（topology=parallel, dag_layers=1）
T3 (sniffing/*)          ┘
```

| 任务 | target_files | bench 基线 | 期望 | 依赖 |
|------|-------------|-----------|------|------|
| T1 | component/daedns/client.go | （无 bench） | effective | — |
| T2 | control/tcp_copy_engine.go | RelayCopyLoop_1MB=9 allocs/op | effective | — |
| T3 | component/sniffing/*.go | SnuffUdp_QUIC=69 / Multi=160 allocs/op | effective_or_noop | — |

## 4. target_files（H4：含关联文件）

- **T1**：`component/daedns/client.go`（H4 应用 — Sprint 1 A5 严守 router.go 错失机会；client.go 是 router.go 同模块同 udpDNSBufPool 的关联文件，含全部 per-query buffer）。
- **T2**：`control/tcp_copy_engine.go`。
- **T3**：`component/sniffing/*.go`（Dev 实施时按 grep 精确到具体文件，bench 函数定义在 component/sniffing/benchmark_test.go:45，被测代码在同包）。

## 5. verifiable_gates（见 frontmatter gates 段）

H1 关键修正：`ci_gate_ebpf_test.local = runs`（Sprint 1 误标 ignored，本机实跑 PASS）。
H2 关键约束：`benchmark_no_regression` 须记录每任务 bench 前后 allocs/op；allocs/op=0 热点不得设 task。

## 6. 编辑规范（Dev 阶段）

- 源码首选 `replace_string_in_file`（L7：禁 PowerShell inline 编辑源码）。
- 代码注释 / commit message **必须英文**（AGENTS.md 硬规则）。
- WSL 命令脚本化（H3）：写 tmp/*.sh 再 `wsl -d Ubuntu -- bash <script>`，禁 inline `$`。
- control 包任何操作先 `make ebpf` 再带 `-tags=$(cat .build_tags)`（F1）。

## 7. 开放问题 / Open Questions

- OQ-S2-1：T3 sniffing QUIC 的 69-160 allocs 中，密码学（Keys/NewKeys）占比？Dev 须先量化再决定可消除范围；若全为密码学内禀 → 诚实 no-op（H2 允许，须分析论证）。
- OQ-S2-2：T1 无 bench，如何量化收益？— 靠 race+vet+test + L4 安全条件论证；如 Dev 认为有必要可加一个 lookupType bench（可选，非强制，避免 scope 膨胀）。
