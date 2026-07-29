---
sprint: 3
sprint_theme: "Memory optimization via H5 (bench + memprofile dual verification) / 基于 H5 的内存优化（bench+memprofile 双验证）"
phase: planning
owner: Remy
branch: kdae
created: 2026-07-29
content_language: bilingual
prev_sprint: 2
drift_check: docs/sprint-3/drift-check.md
h5_applied: true

# === blast_radius（plan 锁定，执行期不得超）===
blast_radius:
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true
  hard_cap: 10
  commit_budget: 2
  commit_budget_formula: ceil(task_count/3) + strong_coupling_count + 1
  commit_budget_derivation: "ceil(1/3) + 0 + 1 = 2（task_count=1, strong_coupling=0；T1 单文件单点改动）"
  commit_budget_risk_note: >
    H5 过滤后仅 1 个生产 residual task。budget=2 = 1 code commit + 1 buffer（docs/progress）。
    即使 T1 bulk 部分判 inherent no-op，errStrLower 的零分配改写本身是 1 个有效 code commit，
    不超 budget。thin Sprint 是 H5 应用于已优化 2 Sprint 代码库的正确预期。

# === task_sizing ===
task_sizing:
  task_count: 1
  strong_coupling_count: 0
  dag_layers: 1
  topology: serial
  topology_rationale: "单 task，无并行/耦合"

# === task DAG（每 task 标注 memprofile flat% 证据）===
tasks:
  T1:
    name: "UdpProxyDial cache=miss create 路径：消除 errStrLower 冗余字符串分配 + 文档化 bulk inherent"
    source: "H5 bench+memprofile（Sprint 2 semi-cold 候选，memprofile 复核为 PROD）"
    target_files: ["control/udp_endpoint_pool.go"]
    target_sites:
      - "errStrLower @1235 = strings.ToLower(err.Error())  ← 唯一可消除 residual"
      - "isConnectionRefused @1201（errStrLower 唯一调用点，ICMP-refused 错误路径）"
    memprofile_evidence:
      bench: "BenchmarkUdpProxyDial/cache=miss = 18 allocs/op 5230B/op"
      h5_verdict: "PROD（~30% harness + ~70% prod；通过 H5 过滤，非 harness noise）"
      prod_flat_pct:
        isConnectionRefused: "12.65%（含 errStrLower 的 strings.ToLower alloc）"
        context.WithDeadlineCause: "11.30%（inherent：拨号超时，2 处）"
        registerEndpoint: "10.13%（inherent：map 插入新 endpoint）"
        time.NewTimer: "10.12%（inherent：随 WithTimeout）"
        createEndpointLocked: "7.28%（inherent：&UdpEndpoint{} + lifecycle profile）"
      eliminable_residual: "errStrLower 的 strings.ToLower → 零分配大小写不敏感子串匹配"
      bulk_inherent_note: "context/timer/struct/map 四类 = 拨号超时机制 + endpoint 对象本身 + 索引注册，语义不可消除；Dev 须在 progress 文档化为 inherent no-op（非 silent failure）"
    depends_on: []
    bench_coverage: yes
    bench_baseline: {UdpProxyDial_cache_miss: "18 allocs/op"}
    pool_reuse: "无（零分配大小写不敏感匹配，非池化）"
    safety_condition: "语义保持：大小写不敏感匹配 'connection refused'/'port unreachable'/'host unreachable' 三个子串，匹配结果与 strings.ToLower+Contains 完全一致（ASCII；错误消息无非 ASCII）"
    expected: effective_small
    noop_risk: "errStrLower 在错误路径（非稳态热路径），bench 数字可能不降（若 bench 未真实触发 refused）；但消除的 alloc 真实存在于生产 ICMP-refused 处理。bulk 部分 inherent，Dev 须诚实文档化。"

# === verifiable_gates ===
gates:
  go_vet:        {cmd: "go vet -tags=$(cat .build_tags) ./...", target: clean}
  go_build:      {cmd: "go build -tags=$(cat .build_tags) ./...", target: ok}
  go_test:       {cmd: "go test -tags=$(cat .build_tags) ./control/... ./component/...", target: pass}
  go_test_race:  {cmd: "go test -tags=$(cat .build_tags) -race ./control/...", target: pass, reason: "T1 涉及 udp_endpoint_pool（isConnectionRefused 在读循环），race 必跑"}
  benchmark_no_regression:
    cmd: "go test -tags=$(cat .build_tags) -bench='UdpProxyDial' -benchmem -run='^$' -benchtime=300ms ./control/"
    target: "allocs/op 不增；errStrLower 命中则降（若 bench 未真实触发 refused，允许持平——须 memprofile 复核 errStrLower flat 是否消失）"
    h5_verification: "Dev 改后须重跑 memprofile 确认 errStrLower/strings.ToLower flat 消失；bulk inherent 部分 flat 保持（context/timer/struct/map）——这是 H5 验证改进生效的证据"
  memprofile_review:
    cmd: "go test -tags=$(cat .build_tags) -bench='UdpProxyDial$' -memprofile=/tmp/t1-after.mem -run='^$' -benchtime=300ms ./control/ && go tool pprof -top -sample_index=alloc_objects -nodecount=20 /tmp/t1-after.mem"
    target: "strings.ToLower / errStrLower 不再出现在 top（被消除）；isConnectionRefused flat 下降或归零"
    reason: "H5：memprofile 复核是 T1 的核心验证（bench 数字因错误路径触发率可能不变，memprofile 是决定性证据）"
  ci_gate_ebpf_test: {cmd: "make ebpf-test", local: runs, note: "H1 持续；T1 无 .c 改动，回归安全"}
  ci_gate_make_da_ebpf: {cmd: "make ebpf", local: runs}
  ebpf_lint: {cmd: "make ebpf-lint", target: na, note: "无 .c 改动"}
  ebpf_sync_check: {cmd: "make ebpf-sync-check", target: pass, note: "无 C 结构体改动"}
  no_behavior_change: {target: "config/CLI/API/错误码不变；isConnectionRefused 返回值在所有错误输入下与改前逐位一致（语义保持）"}

# === H5 eval 回归验证（drift-check §5 要求显式写出）===
eval_regression_verification:
  H5: >
    本 Sprint = H5 首次应用。验证方式：Producer 阶段已对全部 allocs/op>0 热点跑 memprofile 分类
   （runtime-context.md §H5 表）。H5 生效证据 = (a) 最大热点 WriteToBufferFlush(60 allocs/3.6MB)
    经 memprofile 判为 95.73% harness noise 而未设 task（H5 过滤生效，对标 Sprint 2 T2 的事后才发现）；
    (b) 仅 PROD 残留 errStrLower 设 task，crypto-inherent(B)/lifecycle-boundary(C) 全排除。
    Sprint 结束统计：harness-noise task 数应 = 0（H5 在 Producer 阶段即过滤，对标 Sprint 2 T2 的 Dev 阶段才发现）。
  H1: "ci_gate_ebpf_test.local = runs（Sprint 2 起，本 Sprint 延续），无 ignored 回归"
  H2: "T1 来自 bench 调研 allocs/op>0（UdpProxyDial/cache=miss=18），非静态 grep"
  H3: "全程 tmp/*.sh（sprint3-env/fidelity/survey/mem2.sh），gate exit 可靠"
---

# Sprint 3 Plan — 基于 H5 的内存优化（bench + memprofile 双验证）

> 延续 Sprint 1/2 内存优化方向。**核心区别 = 应用 H5**：在 Producer 规划阶段即用 memprofile 验证每个热点的生产相关性，从源头消除 harness 噪声 task（Sprint 2 T2 是 Dev 阶段才发现 harness noise；Sprint 3 在 Producer 阶段就过滤）。
> 输入：[drift-check.md](drift-check.md) + [runtime-context.md](runtime-context.md) §H5 分类表 + Sprint 2 hill-climbing.md。

## 1. 目标 / Goals

- **T1（H5 验证后的唯一生产 residual）**：消除 `UdpProxyDial cache=miss` create 路径中 `errStrLower` 的 `strings.ToLower` 冗余字符串分配（零分配大小写不敏感子串匹配），并文档化 bulk inherent allocs（context/timer/struct/map）。
- **整体**：所有改动**语义保持**（`isConnectionRefused` 返回值逐位一致），通过完整 gate + memprofile 复核。

## 2. 非目标 / Out-of-Scope（本 Sprint 不做什么）

- ❌ WriteToBufferFlush（60 allocs/3.6MB）—— **H5 memprofile 判为 95.73% harness noise**（net.IPv4 76.58% + net.listenTCPProto 19.15%），生产 `ConnSniffer.WriteTo` flat=0。H5 硬约束：harness noise 不得设 task。
- ❌ Sniffer_SniffUdp_QUIC（67/160）—— 59% crypto-inherent；非密码学残留全为 Sprint-2-exhausted（T3 已做）或 lifecycle-boundary（ExtractCryptoFrameOffset/NewLinearLocator，Sprint 2 已标 Sprint+1）。
- ❌ Sniffer_SniffTcp_TLS/HTTP（18/16）及 async-read 变体 —— 主 allocs 为 sniffer-lifecycle 重构（NewStreamSniffer 11% + async-goroutine 19%）= Sprint 2 显式 deferred，超语义等价边界（用户硬约束）。
- ❌ 锁合并/重排、巨型文件拆分、测试瘦身、行为/API/config 变更、新协议。
- ❌ eBPF C（Sprint 1 B1/B2 已证无真冗余）。
- ❌ 冷路径（CloneCacheForReload）、test-only 函数（DnsCache_Clone/FillInto*，L2）。
- ❌ 不碰 vendor / vmlinux-*.h / fork（quic-go、outbound）。
- ❌ errStrLower 之外的 bulk inherent（context.WithTimeout ×2、&UdpEndpoint{} 结构体、newDataSessionLifecycleProfile、registerEndpoint map 插入）—— Dev 须**文档化为 inherent no-op**，不得为降 bench 而改语义。

## 3. 任务 DAG / Task DAG

```
T1 (control/udp_endpoint_pool.go)   单 task，serial，dag_layers=1
```

| 任务 | target_files | bench 基线 | memprofile 结论 | 期望 | 依赖 |
|------|-------------|-----------|----------------|------|------|
| T1 | control/udp_endpoint_pool.go | UdpProxyDial/cache=miss=18 allocs/op | PROD（~70% prod）；bulk inherent，residual=errStrLower | effective_small | — |

## 4. H5 分类汇总（决策依据，详见 runtime-context.md §H5）

| 候选 | allocs/op | H5 结论 | 处置 |
|------|-----------|---------|------|
| D WriteToBufferFlush | 60 | HARNESS（95.73% net.IPv4+listen） | **过滤**（H5 标杆案例） |
| B SniffUdp_QUIC | 67/160 | 59% crypto + Sprint-2-exhausted | 排除 |
| C SniffTcp_TLS | 18 | sniffer-lifecycle-boundary | 排除（Sprint+1） |
| A UdpProxyDial cache=miss | 18 | PROD，bulk inherent，residual=errStrLower | **T1** |

## 5. verifiable_gates（见 frontmatter gates 段）

**H5 关键**：`memprofile_review` gate 是 T1 的决定性验证——errStrLower 在错误路径，bench 数字可能不降（取决于 bench 是否真实触发 refused）；memprofile 确认 `strings.ToLower` flat 消失才是改进生效的硬证据。

## 6. 编辑规范（Dev 阶段）

- 源码首选 `replace_string_in_file`（L7：禁 PowerShell inline 编辑源码）。
- 代码注释 / commit message **必须英文**（AGENTS.md 硬规则）。
- WSL 命令脚本化（H3）：tmp/*.sh → `wsl bash`，禁 inline `$`。
- control 包任何操作先 `make ebpf` 再带 `-tags=$(cat .build_tags)`（F1）。
- memprofile 须**逐包**跑（F3：-memprofile 不可跨多包）。

## 7. 开放问题 / Open Questions

- OQ-S3-1：`errStrLower` 在 bench `cache=miss` 中占 isConnectionRefused flat 的一部分。Dev 须确认 bench 是否真实触发 refused 路径（决定 bench 数字是否下降）；无论 bench 是否下降，memprofile 复核 strings.ToLower flat 消失即改进生效。**闭环方式**：Dev 改后跑 memprofile_review gate，记录 strings.ToLower flat before/after。
- OQ-S3-2：是否值得把 bulk inherent（context/timer/struct/map）逐条写进 progress 的"文档化 no-op"段？**是**——H5 要求 harness/inherent 判定有据可查，避免被误读为 silent no-op。
