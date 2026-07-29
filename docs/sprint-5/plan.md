---
sprint: 5
sprint_theme: "Tech debt cleanup + measurement precision upgrade (H8 first application) / 技术债清理 + 测量精度升级（H8 首次应用）"
phase: planning
owner: Remy
branch: kdae
created: 2026-07-29
content_language: bilingual
prev_sprint: 4
drift_check: docs/sprint-5/drift-check.md
runtime_context: docs/sprint-5/runtime-context.md
constraint_policy: test_pruning_and_cpu_algo_allowed
h1_applied: true
h3_applied: true
h4_applied: true
h5_applied: true   # T2 memprofile 交叉验证（CPU 驱动任务的 alloc 旁证）
h6_applied: true   # fidelity 按扩展名（Sprint 5 仅改 .go）
h7_applied: true   # T2 verdict 必须含 CPU 维度（不能用 bench allocs 判）
h8_applied: true   # 首次应用：T3 bench harness deadline 化
h9_evaluated: true # 已评估：T1/T3 sniffing 测试包编译耦合 → 强制 sequential

# === blast_radius（plan 锁定，执行期不得超）===
blast_radius:
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true
  hard_cap: 10
  commit_budget: 5
  commit_budget_formula: dag_layers + strong_coupling_count + bug_reserve
  commit_budget_derivation: "dag_layers=3（T1→T2→T3 全串行）+ strong_coupling=1（T1/T3 共享 sniffing 测试包，删除可能触及 benchmark_test.go 依赖的 helper 或同包测试，编译级耦合）+ bug_reserve=1（T1 helper 依赖链恢复风险，ai-test-pruning.md 明示『最易踩坑』）= 5"
  commit_budget_risk_note: >
    5 = 3 task code commits + 1 helper 链恢复 buffer + 1 race/回归/docs buffer。
    T1 是删除密集型（预计删 ~100 文件），helper 依赖链断裂是最常见中断源（需 go vet 驱动逐个恢复），
    bug_reserve=1 必要。T2 纯算法低风险；T3 仅改测试 harness 不动生产。
    全串行因 T1/T3 同 sniffing 测试包编译耦合（H9 评估结论），不可降级并行。

# === task_sizing ===
task_sizing:
  task_count: 3
  strong_coupling_count: 1
  dag_layers: 3
  topology: sequential
  topology_rationale: >
    用户建议 sequential 且 H9 评估确认无法证明 target_files 完全互斥：
    T1 删除 sniffing 包批量测试，T3 修改 component/sniffing/benchmark_test.go（同包），
    删除若触及 benchmark_test.go 依赖的 helper 或同包类型 → 编译断。
    即便文件级不重叠（T3 目标 benchmark_test.go 非 T1 删除候选），包级编译耦合存在。
    顺序 T1→T2→T3：先瘦身测试基座，再改生产 http.go，最后改 bench harness。

# === 可行性前置 gate（v5.0 普适 G1/G2 + perf 专属 G3/G4）===
feasibility_gate:
  T1:
    type: test_pruning  # 非生产 perf，G1/G2 不适用；改用删除保护 gate
    deletion_protection: "PASS — comm -12 验证：只删 85a1fc3c/0486201e/b7fb496d 批量添加的；2023 原生 16 个（bitlist/ip46/dialer_group/socks/ahocorasick/cipher/quic/tls/marshal/outline/packet_sniffer_pool/config_parser/trie 等）绝不碰"
    categorization_done: true
    helper_chain_risk: "高 — go vet 驱动逐个恢复（ai-test-pruning.md §helper 依赖链处理）"
  T2:
    type: perf_cpu  # CPU 驱动，非 alloc 驱动
    G1_liveness: "PASS — sniffHTTPHostHeader @http.go:21 ← SniffHttp @http.go:67 ← 生产嗅探路径（NewStreamSniffer→SniffTcp/SniffHttp）"
    G2_heat: "PASS — warm（每 HTTP 连接嗅探触发）"
    G3_bench: "conditional — T2 是 CPU 驱动非 alloc 驱动；G3(allocs>0) 为旁证非决定性（见 OQ-S5-1）"
    G4_memprofile: "conditional — 目标是 CPU flat；string() 转换若有 alloc 则 G4 旁证"
    H7_cpu_evidence: "决定性 — sniffHTTPHostHeader cum 16.85% / bytes.Index cum 9.95%（S4 H7 CPU profile，OQ-S4-3）"
    premise_check: "⚠️ 用户描述『用 bytes.Index 替代手写字节扫描』与实际不符——http.go 已用 bytes.Index/bytes.Cut/bytes.EqualFold。真实优化空间=减少 per-line rescan（循环每行对 data[lineStart:] 重复 bytes.Index）+ 消除 string() 转换分配 + 跳过 request line。见 OQ-S5-1"
  T3:
    type: harness_improvement  # H8 首次应用，非生产 perf
    G1_liveness: "PASS（harness 侧）— benchmark_test.go 测的是 LIVE 生产代码（NewStreamSniffer/SniffTcp/SniffUdp）；harness 改进使 bench 更贴近生产"
    H8_evidence: "PASS — bytes.NewReader 无 SetReadDeadline（benchmark_test.go:18,38,125）→ 强制 async 路径（readStreamOnceAsync），而生产 TCP 走 deadline_sync_read（sniffer.go:170 s.conn.SetReadDeadline）。L14 async 偏差实证"
    scope_lock: "只改 benchmark_test.go，不动 sniffer.go 生产读路径（H8 是 harness 改进非生产改动）"

# === task DAG ===
tasks:
  T1:
    name: "AI 批量测试瘦身：删除 commit #970(85a1fc3c,136) / 0486201e(55) / b7fb496d(15) 批量添加的冗余测试，保留 helpers/fuzz/每模块1-2核心契约"
    source: "用户锁定方向 + /memories/ai-test-pruning.md（dae 实例方法论）+ 203 test:197 src=1.03（健康区间 0.3-0.5）"
    methodology: "/memories/ai-test-pruning.md（识别→分类→删除保护→helper 链恢复→验证三件套）"
    target_files:
      # 删除候选（批量 commit 添加的，按分类）
      - "oneshot(9): control/dns_cache_race_test.go, control/udp_dispatch_fix_test.go, control/udp_dispatcher_lifecycle_regression_test.go, control/udp_hy2_simulation_test.go, control/udp_quic_initial_regression_test.go, control/udp_reply_slo_test.go, control/udp_reuse_simulation_test.go, control/udp_task_pool_race_fix_test.go, control/udp_upstream_instability_simulation_test.go"
      - "bench(8, 删非基线的): control/{dns_cache,runtime_stats,tcp_copy_engine,udp_dispatcher,udp_proxy_dial,udp_quic_e2e}_bench_test.go, component/{routing/domain_matcher/thp, sniffing/internal/quicutils/cipher}_bench_test.go"
      - "functional(选择性删，每模块保留1-2核心契约): #970 的 106 + 0486201e 的 50 + b7fb496d 的 15 中依赖真实网络/eBPF特权/单文件>400行/同模块重复覆盖者"
      # 保留硬规则（绝不删）
      - "KEEP helpers(9): cmd/run_test_helpers, component/outbound/dialer/recovery_test_helpers, component/routing/domain_matcher/test_helpers, control/{bpf,control_plane_real_domain,dns_runtime,packet_sniffer_pool,tcp_copy}_test_helpers, control/kern/tests/bpf_test_helpers"
      - "KEEP fuzz(6): cmd/runtime_supervisor_fuzz, component/sniffing/{http,quic,tls}_fuzz, component/sniffing/internal/quicutils/cipher_fuzz, control/dns_cache_fuzz"
      - "KEEP 原生(16, 2023): common/{bitlist,netutils/ip46}, component/outbound/{dialer_group,dialer/socks/socks}, component/routing/domain_matcher/{ahocorasick_slimtrie,benchmark}, component/sniffing/{internal/quicutils/cipher,quic_bench,quic,sniffing_bench,tls}, config/{marshal,outline}, control/packet_sniffer_pool, pkg/{config_parser,trie}"
      - "KEEP T3 目标: component/sniffing/benchmark_test.go（Sprint 4 创建，非批量 commit）"
    deletion_protection: "comm -12 delete_candidates.txt <(git show 85a1fc3c+0486201e+b7fb496d 新增) 只删批量加的；原生绝不碰"
    helper_chain_recovery: "go vet ./... 驱动 → undefined: xxx → git grep 定位 → 排除假阳性（源码构造函数）→ 真 helper 恢复到集中 helper 文件（注意 build tag 一致 + 依赖链深化）"
    expected: "删除 ~100-120 文件，test:src 从 1.03 降至 ~0.5（健康区间）；保留 ~80-100（helpers+fuzz+核心契约+T3目标）"
    noop_risk: "低（删除是确定性收益）；主要风险是 helper 链断裂导致编译失败（bug_reserve 覆盖）"
    depends_on: []
  T2:
    name: "sniffHTTPHostHeader CPU 热路径优化：减少 per-line bytes.Index rescan + 消除 string() 转换分配 + 跳过 request line"
    source: "S4 H7 CPU profile（sniffHTTPHostHeader cum 16.85% / bytes.Index cum 9.95%，OQ-S4-3）+ L12（CPU/GC 收敛）"
    target_files:
      - "component/sniffing/http.go"   # sniffHTTPHostHeader @21 + SniffHttp @67（仅 75 行，范围严控）
    target_sites:
      - "sniffHTTPHostHeader @21 循环：每行 bytes.Index(data[lineStart:], httpLineSep) 重复 reslice+rescan"
      - "@37 key/value 经 bytes.Cut + bytes.TrimSpace + bytes.EqualFold 每行重复"
      - "@45 string(bytes.TrimSpace(value)) 分配（每命中 Host 转换）"
      - "@67-73 SniffHttp：string(method) 转换 + common.IsValidHttpMethod(string(method))"
    liveness_gate: "G1 PASS — sniffHTTPHostHeader←SniffHttp←生产嗅探"
    heat_gate: "G2 PASS — warm（每 HTTP 连接）"
    cpu_profile_evidence:
      cum: "sniffHTTPHostHeader cum 16.85% / bytes.Index cum 9.95%"
      insight: "纯 CPU 算法热点（非 GC 驱动，与 S4 lifecycle 重构的 alloc 热点不同维度）；优化=减少扫描次数+消除 string 分配"
    h7_verdict_dimension: "verdict 必须含 CPU 维度（H7）：改后 cpu_profile sniffHTTPHostHeader cum% 下降 + bytes.Index cum% 下降。不可仅用 bench allocs/op 判（OQ-S5-1）"
    scope_lock: "YAGNI — 只动 sniffHTTPHostHeader/SniffHttp 路径，不扩散到 tls.go/quic.go/sniffer.go 其他嗅探函数"
    pool_guard: "L13 — 本 task 不碰池化（纯算法），L13 不触发；若 Dev 评估需池化须加 readerLingering 式守卫"
    expected: "effective_small — CPU 热点下降（cum% 个位数到更低）；string() 分配若消除则 bench allocs 降"
    noop_risk: "中 — http.go 已较紧凑（75行已用 bytes 原语），优化幅度取决于 request line 跳过 + rescan 消除的实际收益；CPU 收益为主、alloc 收益为辅"
    depends_on: [T1]
    depends_on_rationale: "T1 先瘦身测试基座（删 http_optimization_test.go 等批量测试若属删除候选），T2 在精简后的测试集上验证语义等价"
  T3:
    name: "H8 首次应用：benchmark_test.go harness deadline 化——bytes.NewReader 替换为 net.Pipe+SetReadDeadline（或等价 deadline-supporting conn）"
    source: "S4 L14（bytes.Reader 无 deadline → 强制 async 路径 readStreamOnceAsync，掩盖生产 TCP deadline_sync_read 真实分配）+ harness-backlog H8（Sprint 5 首次应用）"
    target_files:
      - "component/sniffing/benchmark_test.go"   # 仅此一个文件（harness 改进，不动生产）
    target_sites:
      - "@18 BenchmarkSniffer_SniffTcp_TLS: NewStreamSniffer(bytes.NewReader(tlsStreamGoogle), 300ms)"
      - "@38 BenchmarkSniffer_SniffTcp_HTTP: NewStreamSniffer(bytes.NewReader(payload), 300ms)"
      - "@125 BenchmarkSniffer_SniffTcp_NotApplicable: NewStreamSniffer(bytes.NewReader(payload), 50ms)"
    current_bias_evidence: "bytes.NewReader 实现 io.Reader 但不支持 SetReadDeadline → sniffer.go:160 readStreamOnce 走 readStreamOnceAsync（@194 spawn goroutine + channel）而非生产 deadline_sync_read（@170）→ bench 测的是 async 路径分配，非生产 TCP 真实路径"
    production_reference: "sniffer.go:170 s.conn.SetReadDeadline(s.deadline) 是生产 TCP 主路径（S4 done.md BenchmarkSniffTcpReadStrategy/deadline_sync_read=5 allocs vs legacy_async_read=13）"
    h8_application: "首次应用 H8——verifiable_gates 显式标注 cpu/bench verdict 须用 deadline-sync 路径数据，不可用 async-biased 旧数据"
    scope_lock: "只改 benchmark_test.go（harness），不动 sniffer.go 生产读路径；替换策略=net.Pipe+goroutine 喂数据+SetReadDeadline，或封装 deadlineConn struct"
    expected: "bench SniffTcp_* 的测得 allocs/op 趋近 deadline_sync_read 基线（5 而非 async 的 13），使后续 perf Sprint 的 memprofile 不再被 async 偏差污染"
    noop_risk: "低 — 纯 harness 改进，改完 bench 数字会变（更贴近生产），这是预期而非回归；须在 progress 记录前后对比"
    depends_on: [T2]
    depends_on_rationale: "T3 最后做：T2 改完 http.go 后，T3 在稳定的被测代码上改 harness；且 T1/T3 同 sniffing 测试包，T1 必须先完成（编译耦合）"

# === verifiable_gates ===
gates:
  go_vet:        {cmd: "go vet -tags=$(cat .build_tags) ./...", target: clean}
  go_build:      {cmd: "go build -tags=$(cat .build_tags) ./...", target: clean}
  go_test:       {cmd: "go test -tags=$(cat .build_tags) ./...", target: clean}
  go_test_race:  {cmd: "go test -race -tags=$(cat .build_tags) ./component/sniffing/... ./control/...", target: clean}
  deletion_protection_check:   # T1 专属
    cmd: "comm -12 <(sort delete_candidates.txt) <(git show --diff-filter=A --name-only --format='' 85a1fc3c 0486201e b7fb496d | sort) | diff - <(echo '')"
    target: empty  # 交集应为空（只删批量加的，原生不在交集）
  helper_chain_compiles:       # T1 专属
    cmd: "go vet ./... # undefined: xxx 驱动恢复"
    target: clean
  benchmark_no_regression:     # T2/T3
    cmd: "go test -bench=. -benchmem -run='^$' -tags=$(cat .build_tags) ./component/sniffing/..."
    target: no_regression_or_explained  # T3 预期 bench 数字变化（deadline 化），须记录非回归
  cpu_profile_review:          # H7 — T2 决定性 gate
    cmd: "go test -bench=BenchmarkSniffHTTPHostHeader -cpuprofile -run='^$' ./component/sniffing/... && go tool pprof -top -cum"
    target: sniffHTTPHostHeader_cum_drop  # 改后 cum% < 改前 16.85%；bytes.Index cum% < 9.95%
  h8_deadline_sync_verification:  # H8 首次应用 — T3 决定性 gate
    cmd: "grep -c 'SetReadDeadline\|net.Pipe' component/sniffing/benchmark_test.go"
    target: ">=3"  # 3 个 SniffTcp bench 全部用 deadline-supporting conn
  memprofile_review:           # H5 — T2 旁证（CPU 驱动任务的 alloc 旁证）
    cmd: "go test -bench=BenchmarkSniffHTTPHostHeader -memprofile -run='^$' ./component/sniffing/... && go tool pprof -top"
    target: string_conversion_flat_drop  # string() 转换 flat 消除或确认无目标 alloc
  ci_gate_ebpf_test: {cmd: "make ebpf-test", target: pass, note: "H1 实跑不 ignored；本 Sprint 无 .c 改动，回归安全"}
  ci_gate_make_ebpf: {cmd: "make ebpf", target: exit0}
  ebpf_lint: {cmd: "make ebpf-lint", target: na, note: "无 .c 改动"}
  ebpf_sync_check: {cmd: "make ebpf-sync-check", target: pass, note: "无 C 结构体改动"}
  manual_make_da_validate: {cmd: "make dae && ./dae validate example.dae && ./dae validate /dev/null", target: pass, note: "L8 chmod 0600 临时副本"}
