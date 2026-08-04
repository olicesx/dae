---
sprint: 9
sprint_theme: "Architecture refactor: control_plane_core.go split / 架构重构：control_plane_core.go 拆分"
phase: dev
owner: direct (CEO delegation to kixpower-dev)
branch: kdae
created: 2026-08-05
content_language: bilingual
prev_sprint: 8
constraint_policy: architecture_refactor_allowed

# === constraint_policy 定义（同 Sprint 8） ===
constraint_policy_definition:
  name: architecture_refactor_allowed
  allows:
    - "同包内拆分（提取方法/函数到新文件，package control 不变）"
    - "机械性代码移动（不改逻辑、不改签名、不改 API）"
    - "import 调整（新文件按需 import）"
  forbids:
    - "任何函数逻辑改动"
    - "任何函数签名改动"
    - "任何类型/字段/方法重命名"
    - "跨包移动"
    - "新协议 / 新 feature / config 语言变更"
    - "fork / eBPF C 改动"
    - "test 逻辑改动"

# === blast_radius ===
blast_radius:
  branch_required: true
  target_files:
    - control/control_plane_core.go           # 瘦身（删 ~780 行）
    - control/control_plane_core_bind.go      # 新增（接口绑定 + qdisc 工具，~630 行）
    - control/control_plane_core_routing.go   # 新增（domain routing + udp conn state，~150 行）
  forbidden_files:
    - control/**.go（除上述 3 个）
    - component/**
    - control/kern/**
    - go.mod / go.sum
  max_commits: 5

# === task DAG ===
task_DAG:
  layers: 1   # 串行（都改 control_plane_core.go）
  tasks:
    - id: T1
      name: "拆 control_plane_core.go 到 2 个子系统文件"
      scope: |
        提取 2 个低耦合簇到新文件，同 package control，不改逻辑/签名/API：
        1. control_plane_core_bind.go：接口绑定 + qdisc 工具（~630 行，14 函数）
           - getIfParamsFromLink / linkHdrLen / buildClsactQdisc / addQdisc / delQdisc（tc qdisc 工具）
           - bindLan / _bindLan（LAN 绑定）
           - setupSkPidMonitor / setupTCPRelayOffload（内核 setup）
           - bindWan / registerInterfacePattern / attachMatchingInterfaces / _bindWan（WAN 绑定 + 接口匹配）
           - bindDaens（daens 绑定）
        2. control_plane_core_routing.go：domain routing + udp conn state（~150 行，7 函数）
           - deleteTCFiltersByHandle / extractIPsFromDnsCache（工具）
           - BatchUpdateDomainRouting / BatchRemoveDomainRouting（domain routing）
           - RetainUdpConnStateTuples / TransferRetainedUdpConnStateTuplesFrom / ReleaseUdpConnStateTuples（udp conn state）
      red_green:
        - 三通道语义验证：函数集合一致 + body diff 只机械副产品 + numstat 0/N
        - go build ./control/... 每拆一簇后通过
        - go vet + race + ebpf-test 全过

# === gates ===
gates:
  - go_vet
  - go_build
  - go_test_control_short
  - go_test_race_control       # control_plane_core 涉 bpf hook 并发
  - ebpf_test                  # 确认 C 未触动
  - make_dae                   # CLI 编译
  - dae_validate               # config 解析
  - semantic_three_channel     # 函数集合 / body diff / numstat

# === 风险 ===
risks:
  - id: R1
    topic: "全局 vars 跨簇共享（sharedUdpConnStateTrackerRegistry 等）"
    mitigation: "vars 留 control_plane_core.go；只移方法/函数"
  - id: R2
    topic: "controlPlaneCore struct 字段被各簇方法访问"
    mitigation: "struct 留 control_plane_core.go"
  - id: R3
    topic: "import 误报（参数名匹配包名，Sprint 8 已遇到）"
    mitigation: "dev 用 go build 校验，false positive 由编译器捕获"
