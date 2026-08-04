---
sprint: 6
sprint_theme: "Stability / bug fix harvest (new sprint type) / 稳定性 / bug fix 收割"
phase: planning
owner: Remy
branch: kdae
created: 2026-08-04
content_language: bilingual
prev_sprint: 5
drift_check: docs/sprint-6/drift-check.md
runtime_context: docs/sprint-6/runtime-context.md
constraint_policy: stability_hardening_allowed
h1_applied: true
h3_applied: true
h4_applied: true
h5_applied: true
h6_applied: true
h7_applied: conditional   # 非 CPU 优化主题，race 验证时旁证 GC 维度
h8_applied: true           # bench 非回归用 deadline-sync 数据
h9_applied: true           # 单 task，topology=sequential（无重叠）
h10_deferred: true         # Sprint 6 不涉文件删除，适用条件不满足

# === constraint_policy 定义 ===
constraint_policy_definition:
  name: stability_hardening_allowed
  allows:
    - "行为修复（bug fix）—— 修复真实复现的 bug"
    - "race / 边界加固 —— 修复真实并发 / 边界问题"
    - "权威验证补齐 —— race / ebpf / ebpf-test / bench 非回归验证"
  forbids:
    - "新协议 / 新 feature"
    - "巨型文件拆分（已被游离 commit 做了，不重做）"
    - "eBPF C 改动（tproxy.c）"
    - "config 语言变更"
    - "fork（quic-go / outbound）改动"
    - "语义等价重构（非稳定性主题）"

# === blast_radius（plan 锁定，执行期不得超）===
blast_radius:
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true
  hard_cap: 10
  commit_budget: 3
  commit_budget_formula: dag_layers + strong_coupling_count + bug_reserve
  commit_budget_derivation: "dag_layers=1（单 task T1）+ strong_coupling=0（无跨 task 耦合）+ bug_reserve=2（23 个游离 commit 含巨型文件拆分 59 files/8608 ins/7018 del + 并发改动 sniffer Close guard/janitor + fork bump GSO/buffer race，race/ebpf/bench 回归风险较高；发现多个回归需多个 fix commit）= 3"
  commit_budget_risk_note: >
    3 = 1 验证 commit（若 T1 全过无回归则 0 fix commit）+ 2 bug_reserve（race/ebpf/bench 回归修复）。
    若验证全过：commits_used 可能 0-1（纯验证无需代码 commit）。
    若发现回归：bug_reserve=2 覆盖最可能的修复场景。hard_cap=10 内余量充足。

# === task_sizing ===
task_sizing:
  task_count: 1
  strong_coupling_count: 0
  dag_layers: 1
  topology: sequential
  topology_rationale: "单 task。Sprint 6 是验证+回归修复主题，T1 是确定性基线 gate，无并行需求。H9：单 task 无 target_files 重叠风险。"

# === 可行性前置 gate（v5.0 普适 G1/G2）===
feasibility_gate:
  T1:
    type: stability_verification   # 新类型：权威验证补齐 + 回归修复
    # G1/G2 不适用（验证不是优化特定函数，无 liveness/heat 判定）
    rationale: "T1 是验证 task——对 23 个游离 commit（drift-check §0 既成事实基线）补齐 race/ebpf/bench 权威验证。确定性收益：验证本身有价值（确认稳定性 or 捕获回归）。无 no-op 风险。"
    scope: "验证覆盖全仓库（race/test）+ eBPF 构建链（ebpf/ebpf-test/lint/sync-check）+ 关键 bench 非回归"
    regression_handling: "若验证发现回归 → 在 T1 内修复（bug_reserve=2 覆盖）；修复须通过原 FAIL 的 gate + 全 local_gate 复核"

# === task DAG ===
tasks:
  T1:
    name: "游离 commit 权威验证基线 + 回归修复：补齐 23 个游离 commit（722b123b..HEAD）的 race / ebpf / ebpf-test / lint / sync-check / bench 非回归验证，捕获并修复任何回归"
    source: "drift-check §0 —— Sprint 5 QA 签署后有 23 个游离 commit（巨型文件拆分 + 5 bug fix + fork bump + perf），go vet/test 已 EXIT=0 但 race/ci_gate/bench 未权威验证"
    target_files:
      # 验证范围（非代码改动 target，而是验证覆盖范围）
      - "race: ./... 全仓库（重点 component/sniffing + control，含 sniffer Close guard / janitor event-driven 并发改动）"
      - "ebpf: control/kern/（make ebpf + ebpf-test + ebpf-lint + ebpf-sync-check）"
      - "bench 非回归: component/sniffing/（H8 deadline-sync bench）+ control/（dns/udp dispatch）"
      # 若发现回归，修复 target 由实际 FAIL 的文件决定（bug_reserve 覆盖）
    target_rules:
      globs: ["**/*.go", "control/kern/**", "Makefile"]
      modules: ["control", "component/sniffing", "component/outbound", "cmd", "control/kern"]
      languages: ["go", "ebpf-c"]
      mechanical_links:
        - "Makefile: ebpf / ebpf-test / ebpf-lint / ebpf-sync-check targets"
        - "go test -race: 全仓库并发验证"
        - "go test -bench: sniffing/control 非回归"
    verification_dimensions:
      - {name: "go_test_race", cmd: "go test -race -tags=$(cat .build_tags) ./...", target: clean, note: "23 commit 含并发改动（sniffer Close / janitor），race 必跑"}
      - {name: "ci_gate_make_ebpf", cmd: "make ebpf", target: exit0, note: "deps bump + refactor 可能影响 eBPF 编译"}
      - {name: "ci_gate_ebpf_test", cmd: "make ebpf-test", target: pass, note: "L16/L17：build-tag 门控文件验证"}
      - {name: "ebpf_lint", cmd: "make ebpf-lint", target: clean, note: "refactor 后 C 绑定一致性"}
      - {name: "ebpf_sync_check", cmd: "make ebpf-sync-check", target: pass, note: "Go 绑定与 C 一致"}
      - {name: "bench_no_regression", cmd: "go test -bench=. -benchmem -run='^$' -tags=$(cat .build_tags) ./component/sniffing/... ./control/...", target: no_regression, note: "H8 deadline-sync bench 非回归；refactor + perf 改动可能影响基线"}
      - {name: "manual_make_da_validate", cmd: "make dae && ./dae validate example.dae && ./dae validate /dev/null", target: pass, note: "L8 chmod 0600 临时副本"}
    regression_fix_protocol: >
      若任一验证 FAIL：
      ① 定位根因（git bisect 或 diff 分析锁定引入回归的 commit）；
      ② 最小修复（仅改回归点，不扩散）；
      ③ 修复须通过原 FAIL gate + 全 local_gate 复核（vet/build/test）；
      ④ 记录修复 commit（bug_reserve 覆盖）。
    expected: >
      两种结果（均为有效）：
      (a) 全过：23 个游离 commit 稳定性 proven，基线确认（commits_used=0-1）；
      (b) 发现回归：捕获并修复（commits_used=1-3，bug_reserve 覆盖）。
    noop_risk: "低 —— 验证是确定性收益（确认稳定性 or 捕获回归都是有效产出）"
    depends_on: []
    depends_on_rationale: "单 task，无前置依赖"

# === verifiable_gates ===
gates:
  go_vet:        {cmd: "go vet -tags=$(cat .build_tags) ./...", target: clean, note: "已 EXIT=0（orchestrator 验），T1 复核"}
  go_build:      {cmd: "go build -tags=$(cat .build_tags) ./...", target: clean}
  go_test:       {cmd: "go test -tags=$(cat .build_tags) ./...", target: clean, note: "已 EXIT=0（orchestrator 验），T1 复核"}
  go_test_race:  {cmd: "go test -race -tags=$(cat .build_tags) ./...", target: clean, note: "⚠️ 游离 commit 未验——T1 核心"}
  ci_gate_make_ebpf: {cmd: "make ebpf", target: exit0, note: "⚠️ 游离 commit 未验——T1 核心"}
  ci_gate_ebpf_test: {cmd: "make ebpf-test", target: pass, note: "⚠️ L16/L17 教训——T1 核心"}
  ebpf_lint: {cmd: "make ebpf-lint", target: clean, note: "⚠️ 游离 commit 未验——T1 核心"}
  ebpf_sync_check: {cmd: "make ebpf-sync-check", target: pass, note: "⚠️ 游离 commit 未验——T1 核心"}
  bench_no_regression: {cmd: "go test -bench=. -benchmem -run='^$' -tags=$(cat .build_tags) ./component/sniffing/... ./control/...", target: no_regression, note: "H8 deadline-sync bench；refactor 后基线可能变（记录非回归）"}
  manual_make_da_validate: {cmd: "make dae && ./dae validate -c example.dae && ./dae validate -c /dev/null", target: pass, note: "L8 chmod 0600 临时副本"}

# === 开放问题 ===
open_questions:
  OQ-S6-1:
    question: "游离 commit 的 bug fix 是否有同类未处理边界？（dns UDP size 边界 / sniffer 并发 Close 语义 / janitor timing 边界）"
    handling: "T1 验证后由 Dev/QA 评估。证据驱动——不预设 task。若 grep/审计发现真实未处理边界 → Sprint+1 候选或 T1 扩展（bug_reserve 允许）"
    source: "drift-check §0 bug fix 模式"
  OQ-S6-2:
    question: "巨型文件拆分后是否引入新的编译/测试盲区？（拆分改变 build tag 覆盖 / 包级可见性）"
    handling: "T1 make ebpf-test + go test ./... 覆盖。若发现盲区 → 记录"
    source: "drift-check §0 巨型文件拆分"

# === 本 Sprint 不做什么（Non-Goals）===
non_goals:
  - "巨型文件拆分（已被游离 commit 做了，不重做）"
  - "eBPF tproxy.c 精简（稳定性主题不涉内核态改动）"
  - "新协议 / 新 feature"
  - "fork（quic-go/outbound）改动"
  - "config 语言变更"
  - "语义等价重构（非稳定性主题）"
  - "长驻 reader goroutine（lifecycle Sprint）"
  - "H10 应用（不涉文件删除，deferred）"
  - "预设「可能存在」的 bug fix task（YAGNI——证据驱动，T1 验证后评估）"
