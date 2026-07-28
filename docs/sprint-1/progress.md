---
sprint: 1
sprint_theme: "Semantic-preserving code slimming & runtime-overhead reduction"
phase: planning
owner: Remy
branch: kdae
created: 2026-07-29

# === blast_radius（plan 锁定，执行期不得超）===
blast_radius:
  commit_budget: 5
  commit_budget_formula: ceil(task_count/3) + strong_coupling_count + 1
  hard_cap: 10
  commits_used: 4     # A1(e2e78563) + A2(8e0c17df) + A4(aa7a0891) code + B1/B2 docs(80fba14a); A3/A5 no-op 无 commit
  branch_required: true
  branch: kdae
  block_force_push: true
  block_destructive_sql: true

# === topology ===
topology_used: hybrid
topology_rationale: >
  方向 A（A1-A5）作用于不同 Go 文件，编辑无冲突 → 全并行；
  方向 B（B1→B2）作用于单文件 control/kern/tproxy.c → 串行；
  A/B 语言与文件相互独立 → 整体 hybrid。

# === task DAG 摘要 ===
tasks:
  A1: {status: done, files: [control/dns.go, control/dns_control.go]}
  A2: {status: done, files: [control/udp_ordered_dispatcher.go, control/udp_reply_dispatcher.go, control/udp_ingress_batch.go]}
  A3: {status: done, files: [control/dns_cache.go], note: "no code change - already optimal"}
  A4: {status: done, files: [control/routing_matcher_builder.go]}
  A5: {status: done, files: [component/daedns/router.go], note: "no code change - router.go has no per-query buffer (用户裁定严守 target_files)"}
  B1: {status: done, files: [control/kern/tproxy.c], depends_on: [], note: "no code change - no genuine redundant lookup (IR-verified, each routing map looked up once)"}
  B2: {status: done, files: [control/kern/tproxy.c], depends_on: [B1], note: "no code change - conn_state_map x2 is mandatory lookup→update(create)→reread"}

# === L2 verification（每任务完成后填）===
l2_verification_passed:
  A1: true   # vet+build+race(control) pass; PackBuffer 复用 dnsResponseBufPool
  A2: true   # vet+build+race+bench pass; tasks 预分配 cap=8；ingress_batch 已预分配/复用（验证无改动）
  A3: true   # 验证通过，无代码改动：热路径已 0 allocs/op（见 benchmark 表）
  A4: true   # vet+build+routing test pass；rules/compiledRules/predicateGroups 预分配 cap=len(program.Rules)
  A5: true   # 验证通过，无代码改动（用户裁定严守 target_files=router.go）
  B1: true   # ebpf-lint 0 warn / sync-check pass / build pass; IR 分析：每个 routing map 各查 1 次（active_routing_epoch_map/routing_meta_map 在 route()，routing_map/lpm_array_map/domain_routing_map 在 route_loop_cb，domain_routing_map 已 cache），无冗余
  B2: true   # ebpf-lint 0 warn / sync-check pass / build pass; conn_state_map x2 = lookup→update(create)→reread（被 map 写入分隔，eBPF update 仅返回 int 必须重查取指针），语义必需非冗余

# === verifiable_gates 状态 ===
gates:
  go_vet: pass       # go vet ./... clean
  go_build: pass      # go build -tags=$(cat .build_tags) ./... OK
  go_test: pass       # control(25.7s)+component 全 ok（A1-A5 累积）
  go_test_race: pass  # A1(control,27.9s)/A2(control,11.6s) race 全过；A3/A5 无 Pool 改动；A4 构建期非 Pool
  ebpf_lint: pass       # B1/B2: tproxy.c 0 warning（clean, ready for submission）
  ebpf_sync_check: pass  # B1/B2: 绑定一致，git diff --exit-code 通过（无 C 结构体改动）
  ebpf_test_ci: ignored   # 本机跳过，依赖 CI
  benchmark_no_regression: pass  # A2 SubmitDrain 0 allocs/op；A3 热路径 0 allocs/op；未回归
---

# Sprint 1 Progress — 语义不变的代码精简优化

> 执行期由 Dev/QA 填写。阶段过渡时 Remy 更新本文件与 PROJECT_BRIEF.md 第 7、8 节。

## 状态总览 / Status

| 阶段 | 负责人 | 状态 |
|------|--------|------|
| Planning | Remy | ✅ 完成（brief/brainstorm/plan/runtime-context） |
| Dev | — | ⏳ 待启动 |
| QA | — | ⏳ 待启动 |

## Trace Log

<!-- 每次任务推进追加一行：[时间] task | 动作 | 结果 | commit? -->

- [2026-07-29] A1 | dns_control.go: 4 处响应发送热路径 Pack()→PackBuffer() 复用 dnsResponseBufPool（singleflight/ dialSend / sendDnsErrorResponse_ / sendTruncated）；确认 OQ2=dnsResponseBufPool.New，未重复池化；请求路径 Pack(#2/#3)保留不动 | vet/build/race(control,27.9s)全过 | 待 commit
- [2026-07-29] A2 | ordered/reply dispatcher acquireQueue 预分配 tasks cap=8（默认 const）；确认 ingress_batch slots/msgs 已预分配且 ReadBatch 跨迭代复用（无需改动）；tasks 数组在 runTurn 全排空时 q.tasks[:0] 复用，pre-alloc 仅前置首轮扩容 | vet/build/race(11.6s)/bench(SubmitDrain 0 allocs/op)全过 | 待 commit
- [2026-07-29] A3 | 审查后结论：**无需改动**。生产热路径 GetPackedResponseWithApproximateTTL 已 lock-free 零拷贝（bench 0 allocs/op,3.67ns）；CloneForReload 已 COW 共享 Answer/NS/Extra/packed（prod reload 调用：dns_control.go:357/387/425）；prepackResponseBeforeStore 在每次插入时调用(dns_control.go:2338)保证预打包覆盖；ttlScratchSlice 栈数组保持。desc 点名的 Clone/FillInto/FillIntoWithTTL/FillIntoWithPacked **生产无调用**（仅 test/bench），优化违反 YAGNI；prepackResponseWithTTL 深拷贝为隔离并发 TTL 竞态所必需（in-place 会引入 race，race gate 会挂） | bench 无回归（未改代码）| 待 commit
- [2026-07-29] A4 | routing_matcher_builder NewRoutingMatcherBuilderFromProgram 预分配 rules/compiledRules/predicateGroups cap=len(program.Rules)（每条规则≥1 predicate，安全下界）；simulatedDomainSet/simulatedLpmTries 保留 nil（计数依赖规则类型非规则数）；finalize 已用 make([]T,len) 精确拷贝+nil 释放，无长期 over-alloc | vet/build/routing test(0.42s)全过 | 待 commit
- [2026-07-29] A5 | 审查后结论：**router.go 无 per-query 响应 buffer**。Router 结构体无 buffer 字段，方法全为 upstream-selection/bootstrap/dialer-wrapping（grep make/Pack/WriteMsg/Write 命中仅 map/slice）。真正每查询 buffer 分配在 **client.go**（sendStreamDNS req/lengthBuf/respBuf @556-571、queryHTTPS io.ReadAll @542、lookupType msg.Pack @253），但 client.go 不在 A5 target_files 内。**用户裁定：严守 target_files**，A5 为验证 no-op，client.go 机会记为 OQ4/Sprint+1 候选 | daedns test(0.36s)通过，无回归（未改代码）| 待 commit
- [2026-07-29] B1 | 审查后结论：**无需改动**。按 D2 用 `clang -O2 -g -emit-llvm -target bpf` 生成全文件 IR，按 `__noinline` 函数统计 surviving lookup（clang 已 DCE）。结果：`route()` 中 active_routing_epoch_map x1(zero_key) + routing_meta_map x1(epoch_slot) + route_ctx_scratch_map x1（scratch 禁动）；`route_loop_cb()` 中 routing_map x1 + lpm_array_map x1 + domain_routing_map x1（已由 ctx->domain_word_cached 缓存按 32-rule word 刷新）。**每个 routing map 各查 1 次**，不同 map/不同 key/不同函数，无同函数内被调用阻断的真重复。合并会改变语义（如把 epoch_slot lookup 提前到 zero_key 失败分支）| ebpf-lint 0 warn / sync-check pass / build pass / 基线 route=173 route_loop_cb=210 insns | 待 commit
- [2026-07-29] B2 | 审查后结论：**无需改动**。IR 分析 `__mark_udp_seen`/`__mark_tcp_seen` 各 conn_state_map x2 + bpf_stats_map x1。plan 点名的 tproxy.c:1837/1907（udp）、1956/2046（tcp）正是 **lookup#1（初读现有 state）→ bpf_map_update_elem(create) → lookup#2（重读取新建条目指针）** 模式：两次 lookup 被 map 写入分隔，lookup#1 返回 NULL/旧值、lookup#2 返回新建值，**永不返回同值**；eBPF `bpf_map_update_elem` 仅返回 int 无指针，重查是获取可写指针的唯一手段（verifier 亦要求）。bpf_stats_map x1 为 update 失败的溢出计数器。**无真冗余可合并**（合并违反语义且 verifier 拒绝陈旧指针解引用）| ebpf-lint 0 warn / sync-check pass / build pass / 基线 __mark_udp_seen=251 __mark_tcp_seen=272 insns | 待 commit

## Benchmark 前后值（D4 等价性证据）

| 基准 | 基线 allocs/op | 改后 allocs/op | 变化 |
|------|---------------|---------------|------|
| DnsCache_GetPackedResponseWithApproximateTTL (热路径) | 0 | 0 | 已最优，无需改 |
| DnsCache_CloneForReload (reload COW) | 1 | 1 | wrapper 结构体本身，不可避免 |
| DnsCache_Clone (深拷贝) | 9 | 9 | 仅测试调用，YAGNI 不改 |
| DnsCache_FillIntoWithTTL | 11 | 11 | 仅测试调用，YAGNI 不改 |

| eBPF | 基线 instructions | 改后 instructions | 变化 |
|------|-------------------|-------------------|------|
| route (B1 routing core) | 173 | 173 | no-op：IR 验证无真冗余 lookup（每个 routing map 各查 1 次） |
| route_loop_cb (B1 loop body) | 210 | 210 | no-op：routing_map x1/lpm_array_map x1/domain_routing_map x1(已 cache) |
| __mark_udp_seen (B2 conntrack) | 251 | 251 | no-op：conn_state_map x2 = lookup→update(create)→reread，语义必需 |
| __mark_tcp_seen (B2 conntrack) | 272 | 272 | no-op：同上（SYN 新建路径） |

> 基线测量法：standalone `clang -O2 -g -target bpf -DMAX_MATCH_SET_LEN=1024`（CFLAGS 与 bpf2go 一致），指令数 = 符号 size / 8（BPF insn = 8 字节）。clang 18.1.3，bpfel。冗余检测：`clang -emit-llvm` 全文件 IR，按 `__noinline` 函数统计 surviving `bpf_map_lookup_elem` 调用及 map 实参（clang 已做 DCE，残留即真用）。

## Gate 执行记录

_（待 Dev/QA 记录：命令 + 结果）_

- [2026-07-29] B1/B2 | `make ebpf-lint` → tproxy.c/bpf_test.c/trace.c 全部 "no obvious style problems"，LINT_EXIT=0；`make ebpf-sync-check` → `git diff --exit-code` 通过（ebpf_generated.go / ebpf_sync_defs.h 无改动），SYNC_EXIT=0；`go build -tags=trace ./...` → BUILD_EXIT=0。git status 确认仅 docs 脏，**无任何 .c/.go 源码改动**（B1/B2 为验证 no-op）。基线指令数见上表（clang 18.1.3 bpfel，symbol_size/8）。

## 开放问题追踪

- OQ1: `make ebpf-test` 本机 WSL2 kernel 6.18 vs CI matrix 6.6/6.12 → 依赖 CI。
- OQ2: ~~dns_control.go:38 `make([]byte,1024)` 是否为 dnsResponseBufPool.New~~ ✅ 已确认：是 dnsResponseBufPool.New（A1 未重复池化）。
- OQ3: benchmark 基线机器配置 → Dev 首次跑前记录环境。
- OQ4: daedns per-query buffer 池化机会在 **client.go**（sendStreamDNS req/lengthBuf/respBuf @556-571、queryHTTPS io.ReadAll @542、lookupType msg.Pack @253），非 A5 target_files(router.go)。建议 Sprint+1 扩展 target_files 到 client.go：lengthBuf 上栈 `[2]byte`、req/respBuf 沿用 udpDNSBufPool 模式、Pack→PackBuffer。本机基线 i7-14650HX。

## Sprint+1 候选（L4 Hill Climbing 输入，Sprint 结束时由 QA 填）

_（空）_
