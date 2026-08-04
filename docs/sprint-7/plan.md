---
sprint: 7
sprint_theme: "Harness completion (H10 + H12 applied) / harness 完备化"
phase: dev
owner: direct (CEO self-orchestration)
branch: kdee
created: 2026-08-05
content_language: bilingual
prev_sprint: 6
constraint_policy: harness_hardening_allowed
h1_applied: true
h3_applied: true
h4_applied: true
h5_applied: true
h6_applied: true
h7_applied: conditional
h8_applied: true
h9_applied: true           # T1/T2 独立文件域，无 target_files 重叠
h10_applied: true          # 首次应用（本 Sprint 产出）
h11_applied: false         # Dev WSL 操作后 CRLF 检查，本 Sprint 未触发污染
h12_applied: true          # 首次应用（本 Sprint 产出）

# === constraint_policy 定义 ===
constraint_policy_definition:
  name: harness_hardening_allowed
  allows:
    - "新增 harness 脚本（deletion_protection / fork 验证）"
    - "脚本配套的 dry-run / smoke 自验"
    - "必要时的 tmp/ 辅助验证脚本（不入仓）"
  forbids:
    - "源码逻辑改动（任何 .go 业务代码）"
    - "eBPF C 改动"
    - "config 语言变更"
    - "fork（quic-go / outbound）代码改动"
    - "巨型文件拆分（留 Sprint 8）"

# === blast_radius ===
blast_radius:
  branch_required: true
  target_files:
    - scripts/deletion-protection-scan.sh        # T1 新增
    - scripts/fork-cross-repo-test.sh            # T2 新增
    - docs/sprint-7/*                            # 文档
    - PROJECT_BRIEF.md                           # Sprint 7 章节
  forbidden_files:
    - control/**.go
    - component/**.go
    - control/kern/**.c
    - go.mod / go.sum
  max_commits: 3

# === task DAG ===
task_DAG:
  layers: 1   # parallel
  tasks:
    - id: T1
      name: "H10 deletion_protection gate 增强"
      h_origin: H10
      target_files:
        - scripts/deletion-protection-scan.sh
      red_green:
        - RED:  ISSUE-1 案例 control/bpf_bug_verification_test.go → 期望 exit 1 + 4 hits (Makefile:136/151/166/181)
        - GREEN: control/__nonexistent__.go → 期望 exit 0 + 0 hits
        - EDGE: control/kern/tproxy.c → 期望 exit 1（被 Makefile EBPF_LINT_SOURCES + ebpf-audit.sh 引用，非删目标）
      scope: 扫描 Makefile + .github/workflows/*.yml + scripts/*.{sh,pl,py}，按 basename 匹配候选文件

    - id: T2
      name: "H12 fork 依赖跨仓库验证 harness"
      h_origin: H12
      target_files:
        - scripts/fork-cross-repo-test.sh
      scope: 解析 dae/go.mod replace，对每个 fork commit 跑 fork 自己的 go test
      modes:
        default:     advisory（exit 0 即使 fork 测试失败，供 Producer 评估）
        --dry-run:   只解析不跑测试
        --short:     跳过慢 integration test
        --strict:    fork 失败 → exit 1（fork bump 决策时用）
      env_defaults:
        GOPROXY:       "https://goproxy.cn,direct（尊重环境覆盖）"
        FORK_TEST_TIMEOUT: "600（秒，每仓库超时）"

# === gates ===
gates:
  - go_vet
  - go_build
  - go_test_control
  - ebpf_lint
  - T1_smoke_RED
  - T1_smoke_GREEN
  - T2_dry_run
  - T2_full_advisory   # 非阻塞，记录 baseline

# === OQ（开放问题） ===
open_questions:
  - id: OQ-S7-1
    topic: "fork quic-go @ dff8aaa5 自身测试 4 处失败"
    detail: |
      T2 首次应用暴露：dae 引用的 fork commit 在 quic-go 自己的测试套件中有 4 处失败：
      - TestSendConnSendmsgFailures: sendmsg EPERM（WSL2 特权限制，非 fork bug）
      - TestSendStreamCloseForShutdown: mock 期望与实际不匹配（待 fork 修）
      - TestDatagramLoss + panic "failed to parse short header"（fork datagram pool 改动可能引入）
      - TestConstantDelay: integrationtests/tools/proxy（待 fork 修）
    disposition: "T2 advisory 模式捕获；fork 修复是独立工作，不属 dae Sprint 范畴。留 fork 维护者评估。"
