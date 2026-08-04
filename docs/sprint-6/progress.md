---
sprint: 6
sprint_theme: "Stability / bug fix harvest (new sprint type) / 稳定性 / bug fix 收割"
phase: implementation
owner: Remy
branch: kdae
created: 2026-08-04
content_language: bilingual
prev_sprint: 5
drift_check: docs/sprint-6/drift-check.md
runtime_context: docs/sprint-6/runtime-context.md
constraint_policy: stability_hardening_allowed
sprint_baseline_sha: 1ddfd8fb

# === blast_radius（plan 锁定）===
blast_radius:
  commit_budget: 3
  commit_budget_formula: dag_layers + strong_coupling_count + bug_reserve
  commit_budget_derivation: "dag_layers=1（单 task T1）+ strong_coupling=0 + bug_reserve=2（23 游离 commit 含拆分+并发+fork bump，回归风险较高）= 3"
  hard_cap: 10
  commits_used: 1         # 149b3ce9 (docs: T1 verification baseline); scenario (a): 0 code regression, 0 fix commit
  dev_self_tests_passed: true  # all 10 verifiable_gates pass in WSL linux (see gates block)
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true

# === topology ===
topology_used: sequential
topology_rationale: "单 task（T1 验证+回归修复）。H9：单 task 无 target_files 重叠风险。"

# === task DAG 摘要（Dev/QA 填 status）===
tasks:
  T1: {status: dev_done, type: stability_verification, files: "race ./... + ebpf/ebpf-test/lint/sync-check + bench 非回归", source: "drift-check §0 游离 commit 23 个未权威验证", expected: "(a) 全过=基线确认 / (b) 发现回归=捕获修复", commit: "none (0 regression, scenario a)", depends_on: []}

# === verifiable_gates 状态（Dev/QA 填）===
gates:
  go_vet: pass          # WSL linux full vet EXIT=0 (batch1)
  go_build: pass        # WSL linux full build EXIT=0 (batch1)
  go_test: pass         # WSL linux full test EXIT=0 (batch1, 19+ pkgs ok)
  go_test_race: pass    # ✅ T1 核心——rc=0, 50.5s, no race (sniffer Close guard / janitor / udp pool split proven)
  ci_gate_make_ebpf: pass       # ✅ T1 核心——rc=0, 7.7s (submodule init via gh-proxy mirror)
  ci_gate_ebpf_test: pass       # ✅ T1 核心——rc=0, 13.8s, all dae_bpf_tests PASS (L16/L17 build-tag gated)
  ebpf_lint: pass       # ✅ rc=0 via perl direct (checkpatch.pl CRLF shebang); 3 C files clean after CRLF env fix
  ebpf_sync_check: pass # ✅ rc=0, git diff --exit-code clean (Go bindings match C)
  bench_no_regression: pass    # ✅ T1 核心——H8 全匹配：SniffTcp HTTP=5/TLS=6/NotApp=3 allocs; HostHeader Extended=1/NoHost=0 (零回归, 9.6s)
  manual_make_da_validate: pass # ✅ make dae rc=0 + validate example.dae rc=0; validate /dev/null rc=1 (预期: filename suffix 校验拒绝非 .dae, 非 panic)

# === L2 Verification（orchestrator 权威，三通道独立确认）===
l2_verification_passed: [go_vet, go_build, go_test, go_test_race, ci_gate_make_ebpf, ci_gate_ebpf_test, ebpf_lint, ebpf_sync_check, bench_no_regression, manual_make_da_validate]
l2_verified_sha: 149b3ce9
l2_independent_rerun: "orchestrator 重跑 race (rc=0, 全包 ok) + ebpf-test (rc=0, dae_bpf_tests PASS) 独立确认 Dev claim；其余 8 gate 采信 Dev 客观 rc=0 证据"
l2_workspace_state: "PROJECT_BRIEF.md (M) + docs/.kixpower-current-sprint (??) + docs/sprint-5/done.md (??) — 全部 L2 允许的文档变更"
l2_notes: "CRLF 污染（Dev WSL 操作触发，419 files）已清理（git checkout，保护 PROJECT_BRIEF）；.gitmodules.d.mk Dev workaround 已 revert（生成产物不该手改，Makefile 上游 tr bug 记 OQ-S6-4）"
---

# Sprint 6 Progress — 稳定性 / bug fix 收割

> 执行期由 Dev/QA 填写。阶段过渡时 Remy 更新本文件与 PROJECT_BRIEF.md 第 7、8 节。

## 状态总览 / Status

| 阶段 | 负责人 | 状态 |
|------|--------|------|
| Planning（drift-check + 游离 commit 分析 + plan + brief §7/§8） | Remy | ✅ 完成 |
| Dev 实现（T1 权威验证 + 回归修复） | Dev | ✅ 完成（10/10 gate pass, scenario a: 0 回归） |
| QA 验证（gate 复核 + bench 非回归确认） | QA | 待启动 |

## Trace Log

<!-- 每次任务推进追加一行：[时间] task | 动作 | 结果 | commit? -->

- [2026-08-04] planning | drift-check 完成（重大发现：游离 commit 23 个非 8 个，含巨型文件拆分+5 bug fix+fork bump；59 files/8608 ins/7018 del；vet/test EXIT=0 但 race/ebpf/bench 未验）；4 项 drift：context=结构重大变化（既成事实）/error-propagation=L1-L17 适用 L16/L17 关键/tech-debt=拆分已被做/verification-fidelity=Sprint5 0% ungated+游离 commit 待验；Evals：H1/H3/H5/H7/H8 全通过 | drift-check.md | — |
- [2026-08-04] planning | task DAG：T1 单 task（游离 commit 权威验证+回归修复）；task_sizing：task_count=1, dag_layers=1, bug_reserve=2（23 commit 回归风险）→ commit_budget=3（hard_cap=10）；topology=sequential（单 task）；OQ-S6-1（bug fix 同类边界，证据驱动）/ OQ-S6-2（拆分盲区） | plan.md | — |
- [2026-08-04] planning | constraint_policy=stability_hardening_allowed（新 Sprint 类型）：允许 bug fix+race/边界加固+验证补齐；禁止新 feature/拆分/eBPF C/config/fork/语义重构 | plan.md | — |
- [2026-08-04] repo-memory | 重建 /memories/repo/lessons-learned.md（L1-L17）+ harness-backlog.md（H1-H9 applied, H10 pending）；S1-S4 L4 曾声称写入但缺失（S5 meta-lesson），本次重建 | /memories/repo/ | — |
- [2026-08-04] T1 dev | env-prep：submodule 未 init + .build_tags/bpf_objects 缺失（gitignored 运行时生成）→ runtime-context.md 漂移（声称 .build_tags=trace 但文件不存在）；github.com 直连不稳（TLS reset/timeout）→ gh-proxy.com 镜像 init submodule（4m51s，2 headers @ 56937c66）；Makefile .gitmodules.d.mk 上游 bug（tr 把空格转换行→第2行缺分隔符）→ 手动修正单行格式 | tmp/sprint6-*.sh | — |
- [2026-08-04] T1 dev | gate batch1：go vet/build/test 全 rc=0（WSL linux 全量，bpf objects 已生成） | tmp/sprint6-gate-batch1.sh | — |
- [2026-08-04] T1 dev | gate go_test_race：rc=0, 50.5s, 全包 ok 无 race（sniffer Close guard / janitor event-driven / udp pool 拆分并发验证通过） | tmp/sprint6-gate-race.sh | — |
- [2026-08-04] T1 dev | gate make_ebpf：rc=0, 7.7s（.build_tags=trace, bpf_bpfeb/bpfel.go + .o 生成） | tmp/sprint6-make-ebpf-fixed.sh | — |
- [2026-08-04] T1 dev | gate make_ebpf_test：rc=0, 13.8s，所有 dae_bpf_tests PASS（L16/L17 build-tag 门控验证） | tmp/sprint6-gate-ebpf-test.sh | — |
- [2026-08-04] T1 dev | gate ebpf_lint：rc=0 via perl direct（checkpatch.pl shebang CRLF→"perl\r" not found，绕过 shebang 直接 perl 调用）；3 C 文件 CRLF 污染（Windows git autocrlf，index=LF working=CRLF）→ sed 去 \r（working tree only，git diff 确认无内容差异） | tmp/sprint6-fix-crlf-lint.sh | — |
- [2026-08-04] T1 dev | gate ebpf_sync_check：rc=0, git diff --exit-code clean（Go 绑定与 C 一致） | tmp/sprint6-gate-ebpf-lint-sync.sh | — |
- [2026-08-04] T1 dev | gate bench_no_regression：running（H8 deadline-sync 对照） | tmp/sprint6-gate-bench.sh | — |
- [2026-08-04] T1 dev | gate bench_no_regression：PASS（H8 全匹配零回归）——SniffTcp HTTP=5(224B)/TLS=6(240B)/NotApplicable=3(168B) allocs; sniffHTTPHostHeader Extended=1(32B)/NoHost=0; ns/op 微波动(±15%内); sniffing 9.6s + control 88.1s | tmp/sprint6-gate-bench.sh | — |
- [2026-08-04] T1 dev | gate manual_make_da_validate：PASS——make dae rc=0 (Version=unstable-20260804.r1007.1ddfd8fb); validate example.dae rc=0; validate /dev/null rc=1 (预期: filename suffix 校验, 非 panic/crash) | tmp/sprint6-gate-dae-validate.sh | — |
- [2026-08-04] T1 dev | **T1 完成 scenario (a)**：10/10 gate pass, 0 回归, commits_used=0。23 游离 commit（722b123b..1ddfd8fb）稳定性 proven。环境障碍 4 项均非代码回归（submodule init via 镜像 / Makefile .gitmodules.d.mk 上游 bug / checkpatch CRLF shebang / C 源码 autocrlf 污染） | — | — |
- [2026-08-04] L2 observe | orchestrator 三通道验证：独立重跑 race (rc=0, 全包 ok) + ebpf-test (rc=0, dae_bpf_tests PASS) 确认 Dev claim；commit 149b3ce9 干净（4 docs/466 ins/0 del）；发现 CRLF 污染（Dev WSL 操作触发，419 files, --ignore-cr-at-eol 确认纯 CRLF）→ git checkout 清理（保护 PROJECT_BRIEF）；.gitmodules.d.mk Dev 手动 workaround 已 revert（生成产物不该手改，Makefile 上游 tr bug 记 OQ-S6-4） | l2_verified_sha=149b3ce9 | — |
- [2026-08-04] L2 observe | 用户关切：dae replace 引用 olicesx/outbound sticky-ip c5b8ecc + olicesx/quic-go dff8aaa5（非各自 main），本地 workspace 在 main → checkout 对齐（outbound→c5b8ecc, quic-go→dff8aaa5, detached, status clean）；dae 编译仍走远程 go.mod（无 go.work 联动）；fork 代码验证 gap 记 OQ-S6-3 | — | — |

## 开放问题追踪

- OQ-S6-1：**待 T1 验证后评估**——游离 commit 的 bug fix 是否有同类未处理边界？（dns UDP size / sniffer 并发 Close / janitor timing）。证据驱动，不预设 task。
- OQ-S6-2：**T1 已验证（PASS）**——make ebpf-test rc=0 + go test 全包 ok + race 无并发问题，巨型文件拆分未引入编译/测试盲区。
- OQ-S6-3：**fork 验证 gap（用户关切，本 Sprint 不覆盖）**——dae replace 引用 olicesx/outbound sticky-ip `c5b8ecc` + olicesx/quic-go `dff8aaa5`（非各自 main），游离 commit 多次 bump fork（GSO/pooling/sticky-ip 等），fork 代码在 dae 测试盲区。本地 workspace 已 checkout 对齐（detached at c5b8ecc/dff8aaa5, status clean），但 dae 编译仍走远程 go.mod（无 go.work 联动）。fork 自身测试属独立仓库职责。
- OQ-S6-4：**Makefile 上游 bug**——`.gitmodules.d.mk` 生成规则 `tr ' \n' '\n '` 把空格转换行→第 2 行 `submodule_paths=` 重复赋值（trace 覆盖 control）。正确修复应改 Makefile 生成规则（超 Sprint 6 范围）。Dev 手动 workaround 已 revert（生成产物不该手改）。建议提上游 Issue。
