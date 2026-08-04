---
sprint: 8
sprint_theme: "Architecture refactor: control_plane.go split / 架构重构：control_plane.go 拆分"
phase: dev
owner: direct (CEO delegation to kixpower-dev)
branch: kdae
created: 2026-08-05
content_language: bilingual
prev_sprint: 7
constraint_policy: architecture_refactor_allowed

# === constraint_policy 定义 ===
constraint_policy_definition:
  name: architecture_refactor_allowed
  allows:
    - "同包内拆分（提取方法/函数到新文件，package control 不变）"
    - "机械性代码移动（不改逻辑、不改签名、不改 API）"
    - "import 调整（新文件按需 import）"
  forbids:
    - "任何函数逻辑改动（哪怕一个字符）"
    - "任何函数签名改动"
    - "任何类型/字段/方法重命名"
    - "跨包移动（package control 边界不变）"
    - "新协议 / 新 feature / config 语言变更"
    - "fork（quic-go/outbound）改动"
    - "eBPF C 改动"
    - "test 逻辑改动（只移测试位置或不动）"

# === blast_radius ===
blast_radius:
  branch_required: true
  target_files:
    - control/control_plane.go                              # 瘦身（删 ~1500 行）
    - control/control_plane_dns.go                          # 新增（DNS reload + handoff）
    - control/control_plane_datapath.go                     # 新增（datapath commit + listener）
    - control/control_plane_dialtarget.go                   # 新增（dial target + real domain）避开 dial.go
    - control/control_plane_parse.go                        # 新增（Parse* 配置函数）
  forbidden_files:
    - control/**.go（除上述 5 个）# 不动其他 control 文件
    - component/**.go
    - control/kern/**.c
    - go.mod / go.sum
  max_commits: 5

# === task DAG ===
task_DAG:
  layers: 1   # 表面并行，实际都改 control_plane.go → 顺序执行
  tasks:
    - id: T1
      name: "拆 control_plane.go 到 4 个子系统文件"
      scope: |
        提取 4 个低耦合簇到新文件，同 package control，不改逻辑/签名/API：
        1. control_plane_dns.go：DNS reload cache + DNS handoff controller（~300 行）
        2. control_plane_datapath.go：datapath commit/reload + listener socket publish（~700 行）
        3. control_plane_dialtarget.go：dial target + real domain probe（~400 行）
        4. control_plane_parse.go：Parse* 配置函数（~100 行）
      red_green:
        - go build ./control/... 通过（每拆一簇后）
        - go vet ./control/... 通过
        - go test -short ./control/... 通过
        - 0 逻辑改动（diff 应只显示 mv，无字符级修改）

# === gates ===
gates:
  - go_vet
  - go_build
  - go_test_control_short
  - go_test_race_sniffing  # control_plane 涉及并发（bpf flip / dns handoff）
  - ebpf_lint              # 确认未触动 C 源
  - ebpf_sync_check        # Go 绑定与 C 一致
  - manual_make_da_validate

# === 风险 ===
risks:
  - id: R1
    topic: "import 漏掉 / 冗余"
    mitigation: "每拆一簇后 go build 验证；用 goimports 自动修（WSL 已装则用）"
  - id: R2
    topic: "函数边界识别错（多删/少删）"
    mitigation: "用 go build 捕获；保留 control_plane.go 原 git 版本可 diff"
  - id: R3
    topic: "共享类型/vars 误移"
    mitigation: "只移方法/函数；type/var/const 留 control_plane.go 除非单簇独占"
