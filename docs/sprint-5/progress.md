---
sprint: 5
sprint_theme: "Tech debt cleanup + measurement precision upgrade (H8 first application)"
phase: planning
owner: Remy
branch: kdae
created: 2026-07-29

# === blast_radius（plan 锁定）===
blast_radius:
  commit_budget: 5
  commit_budget_formula: dag_layers + strong_coupling_count + bug_reserve
  commit_budget_derivation: "dag_layers=3（T1→T2→T3 全串行）+ strong_coupling=1（T1/T3 sniffing 测试包编译耦合）+ bug_reserve=1（T1 helper 链恢复风险）= 5"
  hard_cap: 10
  commits_used: 0
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true

# === topology ===
topology_used: sequential
topology_rationale: "T1 删 sniffing 包批量测试，T3 改 component/sniffing/benchmark_test.go（同包编译耦合）；H9 评估确认无法证明 target_files 完全互斥 → 强制 sequential。顺序 T1→T2→T3"

# === task DAG 摘要（Dev/QA 填 status）===
tasks:
  T1: {status: done, type: test_pruning, files: "deleted 108 / kept 90 + recovered 3 helper files + restored 3 bulk-infra files", expected: "test:src 1.03→~0.5", actual: "1.03→0.490", source: "ai-test-pruning.md + 用户锁定", commit: 0e673fe7}
  T2: {status: done, type: perf_cpu, files: [component/sniffing/http.go], source: "H7 CPU cum16.85%/bytes.Index9.95%", depends_on: [T1], expected: effective_small, actual: "Extended 126.5→80.91ns(-36%)/NoHost 57.66→32.82(-43%); bytes.Index cum 57.92%→8.66%", h7_gate: "PASS", commit: 1d1021eb}
  T3: {status: done, type: harness_improvement, files: [component/sniffing/benchmark_test.go], source: "L14 async 偏差 + H8 首次应用", depends_on: [T2], expected: "bench SniffTcp 趋近 deadline_sync 基线", actual: "HTTP 5/TLS 6/NotApplicable 3 allocs (was async ~12); pprof 确认 deadline-sync 路径", h8_gate: "PASS (grep-c=5>=3)", commit: d3e5c4a2}

# === Dev L2 verification（Dev 填）===
completed_tasks: 3
artifacts_changed_since_last_observe: ["T1: 108 test files deleted; 3 new helper files (control/{scripted_packet_conn,test_fixtures,dns_message}_test_helpers_test.go); edits to recovery_test_helpers/run_test_helpers/control_plane_real_domain_test_helpers; restored 3 bulk-infra files (udp_quic_initial_regression/udp_reuse_simulation/udp_sniffer_loss)", "T2: component/sniffing/http.go (sniffHTTPHostHeader IndexByte line split + request-line skip; SniffHttp bytes method check)", "T3: component/sniffing/benchmark_test.go (deadlineConn wrapping 3 SniffTcp benches)"]
l2_verification_passed: "all pass (go build + go vet + go test clean across all packages)"
commits_used: 3

# === verifiable_gates 状态（Dev/QA 填）===
gates:
  go_vet: pass
  go_build: pass
  go_test: pass
  go_test_race: pending
  deletion_protection_check: pass   # T1 — all 108 deletes in bulk commits, native 16 untouched
  helper_chain_compiles: pass       # T1 — go vet clean; ~570 lines shared infra recovered to centralized helpers
  benchmark_no_regression: pass     # T2/T3 — T2 sniffHTTPHostHeader -36..-43%; T3 expected shift to deadline-sync baseline (recorded, not regression)
  cpu_profile_review: pass          # H7 T2 — bytes.Index cum 57.92%->8.66%; ns/op -36..-43%
  h8_deadline_sync_verification: pass  # H8 T3 — grep-c=5>=3; pprof confirms deadline-sync path; allocs 5/6/3
  memprofile_review: pass           # H5 T2 — remaining 1 alloc/op is inherent string return; NoHost 0-alloc
  ci_gate_ebpf_test: pending
  ci_gate_make_ebpf: pending
  ebpf_lint: na
  ebpf_sync_check: pending
  manual_make_da_validate: pending
---

# Sprint 5 Progress — 技术债清理 + 测量精度升级（H8 首次应用）

> 执行期由 Dev/QA 填写。阶段过渡时 Remy 更新本文件与 PROJECT_BRIEF.md 第 7、8 节。

## 状态总览 / Status

| 阶段 | 负责人 | 状态 |
|------|--------|------|
| Planning（drift-check + 可行性预检 + plan + brief §7/§8） | Remy | ✅ 完成 |
| Dev 实现（T1 测试瘦身 / T2 http.go CPU / T3 bench harness） | Dev | ✅ 完成（3 commits：0e673fe7 / 1d1021eb / d3e5c4a2） |
| QA 验证（gate 全过 + cpu_profile_review + h8_deadline_sync） | QA | 待启动 |

## Trace Log

<!-- 每次任务推进追加一行：[时间] task | 动作 | 结果 | commit? -->

- [2026-07-29] planning | drift-check 完成（4 项：零技术 context drift / L1-L14 全规避 L9+L14 核心 / S4 Sprint+1 候选三方向全纳入 / fidelity 权威 git-log=0% ungated，脚本 44% 为 SinceDate 窗口假象）；Evals：H1/H3/H5 全通过，H6 持续，H7 持续，H8 首次应用 | drift-check.md | — |
- [2026-07-29] 可行性预检 | tmp/sprint5-survey.sh + tmp/sprint5-t1-categorize.sh：T1 三批量 commit 分类（#970=136/0486201e=55/b7fb496d=15）+ 原生16保护清单；T2 G1/G2 PASS + H7 CPU 证据 + ⚠️用户前提与实际不符（http.go 已用 bytes 原语，OQ-S5-1）；T3 bytes.NewReader@18/38/125 定位 + 生产 deadline_sync_read@170 对照 | runtime-context.md | — |
- [2026-07-29] planning | G1/G2 普适 gate：T2 PASS（live+warm）；T1 用删除保护 gate（comm -12）；T3 用 H8 evidence gate；task_sizing：task_count=3, dag_layers=3, strong_coupling=1, bug_reserve=1 → commit_budget=5（hard_cap=10）；topology=sequential（H9 评估 T1/T3 sniffing 包耦合） | plan.md blast_radius | — |
- [2026-07-29] planning | 开放问题：OQ-S5-1（T2 用户前提 vs 实际，已 reformulate 为减 rescan+消 string 分配）；OQ-S5-2（T1 helper 链深度，Dev 实操定）；OQ-S5-3（T3 net.Pipe vs 自定义 deadlineConn，Dev 选） | plan.md | — |
- [2026-07-29] orchestrator-observe | Producer 产出验证 PASS：4 文件齐全（plan 14.5K/progress 5.8K/drift-check 11.3K/runtime-context 11.5K）+ PROJECT_BRIEF frontmatter sprint:5 更新 + commit_budget=5 派生合理（dag_layers=3+coupling=1+bug_reserve=1，hard_cap=10）+ OQ-S5-1/2/3 闭环设计 + 7 H applied + H9 evaluated + T1 删/留分类预估（删~100-120/留~80-100，test:src 1.03→~0.5）；接受 T2 reformulation（premise_check 诚实 + OQ-S5-1 闭环 + H7 cpu_profile_review 决定性 gate）；goal_drift 检测：PROJECT_BRIEF+98行/sprint-4/progress+3行/sprint-4/done.md(未跟踪,S4 收尾)/sprint-5/*(plan 范围内)，0 out_of_scope | result=ok | 推进 Dev |
- [2026-07-29] T1 dev | 删除保护验证 PASS（108 候选全在批量 commit，原生16零触碰）；helper 链深度恢复（L15 教训：用 `go test -run='^$'` 一次性 surface 全部 undefined 而非迭代 vet）：~570 行共享 infra 恢复到 3 个集中 helper 文件 + 恢复 3 个被非批量 corpus 复用的 bulk-infra 文件（误分类 oneshot）；drop connectivity_test.go（属 mock 生态）；验证三件套全过；test:src 1.03→0.490 | commit 0e673fe7 |
- [2026-07-29] T2 dev | H5 前置 baseline 确认有空间（sniffHTTPHostHeader cum95.81% / bytes.Index cum57.92%）；实施 IndexByte 单字节行分割（替 2 字节 \r\n 搜索）+ 跳 request line + SniffHttp bytes method check（消 string(method) alloc）；H7 verdict PASS：bytes.Index cum 57.92%→8.66%，Extended -36%/NoHost -43%；H5 memprofile 旁证：剩余 1 alloc = Host string 返回 inherent（无 API 改动不可消），NoHost 0-alloc | commit 1d1021eb |
- [2026-07-29] T3 dev | OQ-S5-3 选型：自定义 deadlineConn（包装 bytes.Reader + no-op SetReadDeadline 返 nil）成功——pprof 确认走 readStreamOnceWithReadDeadline（非 async）；bench allocs 降到生产代表值 HTTP 5/TLS 6/NotApplicable 3（原 async ~12）；h8 gate grep-c=5>=3 PASS；断言全过（语义不变）；预期非回归（bench 数字趋近 deadline-sync 基线）| commit d3e5c4a2 |

## 开放问题追踪

- OQ-S5-1：**已闭环（T2）**——premise reformulate 正确。实际优化=IndexByte 行分割（bytes.Index cum 57.92%→8.66%）+ 跳 request line + 消 string(method) alloc。sniffHTTPHostHeader 自身 cum% 因微基准 L14 陷阱未降（唯一工作），但绝对 ns/op -36..-43% + bytes.Index cum 大降 = 有效（非 no-op）。
- OQ-S5-2：**已闭环（T1）**——helper 链深度超 2 层（达 ~5 层簇：scripted family → errorDialer → newTestEndpointDialer → ... → corpus 依赖）。处理：① 恢复小 helper 到集中文件 ② 恢复 3 个被非批量 corpus 复用的 bulk hub 文件（误分类）③ drop 属 mock 生态的 connectivity_test.go。详见 L15 教训记录。
- OQ-S5-3：**已闭环（T3）**——选自定义 deadlineConn（no-op SetReadDeadline 返 nil）。pprof 确认走 deadline_sync 路径（关键判据满足），无需 fallback 到 net.Pipe。
