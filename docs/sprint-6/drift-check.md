---
sprint: 6
check_type: cross-sprint-drift
run_by: Remy
run_at: 2026-08-04
prev_sprint: 5
sprint_theme: "Stability / bug fix harvest (new sprint type) / 稳定性 / bug fix 收割"
constraint_policy: stability_hardening_allowed
verification_fidelity_method: authoritative-git-log
verification_fidelity_h6_applied: true
baseline_note: >
  Sprint 5 后有 23 个游离 commit（722b123b..HEAD），含巨型文件拆分 + 5 bug fix + fork bump。
  这些是「Sprint 5 外既成事实基线」——Sprint 6 不重做，只补权威验证 + 在新结构上规划。
  go vet/test 已 EXIT=0（orchestrator 已验）；race/ebpf/ebpf-test/bench 未做权威验证（→ Sprint 6 T1）。
---

# Sprint 6 — Cross-Sprint Drift check

> 第 6 个 Sprint 强制执行。来源：EvoClaw Drift 章节 + orchestrator L4 Hill Climbing。
> 输入：Sprint 5 `runtime-context.md` / `hill-climbing.md` / `done.md` + `/memories/repo/harness-backlog.md`（H1-H9 applied, H10 pending）+ `/memories/repo/lessons-learned.md`（L1-L17）。

## 0. 游离 commit 清单（722b123b..HEAD，23 个，既成事实基线）

> **重大发现**：Sprint 5 QA 签署（722b123b）之后，有 **23 个 commit**（非任务描述预估的 8 个），含**巨型文件拆分**（S1-5 四次 deferred 的方向已被做）+ 5 个 bug fix + 多个 fork bump。改动规模：**59 files / +8608 / -7018**。

### 按性质分类

| 类别 | commits | 说明 |
|------|---------|------|
| **巨型文件拆分（refactor）** | `cf1db3ad`(run.go→4) / `34c88f99`(dns_control.go→6) / `a9895907`(udp_endpoint_pool.go→3) / `ddb1bd01`(extract runtime structs) / `8acf55d4`(restore doc comments) | **S1-5 deferred 的「巨型文件拆分」已被做**。模块边界重大变化。 |
| **Bug fix（稳定性核心）** | `1ddfd8fb`(dns TC bit) / `28872b0b`(sniffer nil buf guard) / `29f8673b`(drop unused roll) / `41dcf634`(dns black-hole timeout) / `eee7c88b`(preserve dae DNS #1065) | 5 个真实 bug 修复，暴露稳定性问题模式。 |
| **Perf** | `ae2443ec`(janitor event-driven + calm-state backoff) | idle janitor 行为优化。 |
| **Deps bump（fork）** | `e9fb1066`/`274530a2`/`a48fba4c`/`ae056a6a`/`f8be7d27`/`fcf5c580`/`8c34b88b`/`13052594`/`5c450764` | quic-go/outbound fork 多次 bump（GSO/buffer race/HKDF/pool-overflow 等）。 |
| **Cleanup/fmt** | `2a007b39`(remove unused symbols post-pruning) / `44faa46e`(go fmt + ebpf-lint) / `3c725417`(gofmt) / `bcd8e0bd`(merge) | 零散清理。 |

### 验证状态评估

| 验证维度 | 状态 | 证据 |
|----------|------|------|
| `go vet ./...` | ✅ EXIT=0 | orchestrator 已验（终端历史确认） |
| `go test ./...` | ✅ EXIT=0 | orchestrator 已验（19+ 包 ok） |
| `go test -race` | ❌ **未权威验证** | 23 个 commit 含 refactor + 并发改动（sniffer Close guard / janitor），race 风险存在 |
| `make ebpf` | ❌ **未权威验证** | deps bump + refactor 可能影响 eBPF 编译 |
| `make ebpf-test` | ❌ **未权威验证** | L16/L17 教训：build-tag 门控文件只有 ebpf-test 抓到 |
| `make ebpf-lint` / `ebpf-sync-check` | ❌ **未权威验证** | refactor 可能影响 C 绑定一致性 |
| 关键 bench 非回归 | ❌ **未权威验证** | refactor + perf 改动可能影响性能基线 |

> **结论**：游离 commit 的 local_gate（vet/test）已过，但 race/ci_gate/bench 三维度未权威验证。这是 **Sprint 6 T1 的核心任务**（补齐权威验证 + 捕获回归）。

### 新增文件（拆分产物 + 测试）

- `cmd/run_{config,controlplane,reload,serve}.go`（run.go 拆分）
- `control/dns_controller_{bpf,cache,forwarder,handle,response,runtime}.go`（dns_control.go 拆分）
- `control/udp_endpoint_{lifecycle,reply,watcher}.go` + `udp_runtime.go`（udp_endpoint_pool.go 拆分）
- `control/{event_ringbuf,listener_runtime,real_domain_runtime,routing_epoch_runtime}.go`（embedded structs 提取）
- `control/dns_truncate_test.go`（随 `1ddfd8fb` 加入）
- `control/group_override_option_test.go`（随 `eee7c88b` 加入）
- 删除：`control/tcp_copy_test_helpers_test.go`（refactor 过程中移除——Sprint 5 KEEP 列表中的 helper，现为既成事实）

## 1. Context Drift（工具链/环境漂移）

| 项 | Sprint 5 基线 | Sprint 6 实测 | 漂移？ |
|----|--------------|--------------|--------|
| Go | go1.26.0 linux/amd64 | 同（go 命令正常运行，vet/test EXIT=0） | ❌ 无 |
| clang / bpftool | 18.1.3 | 同（本 Sprint 无 .c 改动计划） | ❌ 无 |
| kernel | 6.18.33.2-microsoft-standard-WSL2 | 同（同 WSL 实例） | ❌ 无 |
| `.build_tags` | `trace` | `trace` | ❌ 无 |
| 分支 / 工作树 | kdae | kdae（HEAD=1ddfd8fb） | ❌ 无 |
| **代码结构** | dns_control.go(3635) / udp_endpoint_pool.go(2557) / run.go(巨型) | **已拆分**（dns_controller_*.go 6 文件 / udp_endpoint_*.go 3 文件 / run_*.go 4 文件） | ✅ **重大变化**（既成事实） |
| **go.mod fork** | quic-go/outbound 固定版本 | **多次 bump**（GSO/buffer race/HKDF/pool-overflow） | ✅ **变更**（既成事实） |
| **约束政策** | test_pruning_and_cpu_algo_allowed | **stability_hardening_allowed**（新 Sprint 类型） | ✅ **有意变更** |

**结论：工具链零漂移；代码结构重大变化（巨型文件拆分 + fork bump，既成事实基线）。** Sprint 6 在新结构上规划，不重做拆分。

## 2. Error Propagation（L1-L17 逐条对照 Sprint 6 plan）

| Lesson | 陷阱 | Sprint 6 规避 | 规避？ |
|--------|------|--------------|--------|
| L1 | 诚实 no-op 范式 | T1 是验证 task（确定性收益非 no-op）；若验证全过则 Sprint 6 可能只有验证确认（诚实记录） | ✅ |
| L2 | 点名函数可能是死代码 | Sprint 6 不优化特定函数（稳定性主题）；bug fix 有真实复现路径 | ✅ |
| L7 | PowerShell 调 wsl 转义陷阱 | H3：全程 tmp/*.sh 脚本化 | ✅ |
| L8 | WSL2 可跑 make ebpf-test | T1 补跑 make ebpf-test（游离 commit 未验） | ✅ |
| L9/L14 | bench ≠ 生产 / async 偏差 | T1 bench 非回归验证用 H8 deadline-sync bench（非旧 async 数据） | ✅ |
| L15 | helper 链深度 | Sprint 6 不涉测试删除，不触发 | N/A |
| L16 | Makefile/CI 盲区 | T1 补跑 make ebpf-test 正是抓 build-tag 门控文件断裂（L16 教训）；H10 deferred（不涉删除） | ✅ |
| L17 | gitignored bpf 生成文件 | T1 跑 make ebpf 前确认 bpf objects 生成文件存在（避免环境状态误报） | ✅ |
| L12/L13 | CPU/GC 收敛 / pool 守卫 | Sprint 6 不做 alloc 优化，N/A；但验证 race 时关注 pool 相关并发 | ⚠️ 旁证 |

**结论：L1-L17 全部适用或 N/A。L16/L17 对 Sprint 6 T1 验证游离 commit 特别关键（Makefile 门控 + bpf 生成文件环境状态）。**

## 3. Tech Debt（Sprint 5 遗留 / 游离 commit 已收割 / Sprint+1 候选）

| 来源 | 内容 | Sprint 6 处置 |
|------|------|--------------|
| **游离 commit（既成事实）** | 巨型文件拆分（run.go/dns_control.go/udp_endpoint_pool.go/control_plane.go） | **已被做** —— Sprint 6 不重做；在新结构上验证稳定性 |
| **游离 commit（既成事实）** | 5 bug fix（dns TC bit / sniffer nil buf / dns black-hole / preserve dae DNS / drop unused roll） | **已被做** —— Sprint 6 验证修复正确性 + 评估同类模式 |
| Sprint 5 done.md §7 | H10 应用（deletion_protection gate 增强） | **deferred** —— Sprint 6 不涉文件删除，H10 适用条件不满足 |
| Sprint 5 done.md §7 | eBPF tproxy.c 精简 | **不纳入** —— Sprint 6 稳定性主题，eBPF C 改动 Non-Goal |
| Sprint 5 done.md §7 | 长驻 reader goroutine（lifecycle 高风险） | **不纳入** —— 需独立 lifecycle Sprint |
| 游离 commit bug fix 模式 | dns UDP size 边界 / sniffer 并发 Close / janitor timing | **OQ** —— T1 验证后由 Dev/QA 评估是否有真实同类未处理边界（证据驱动，不预设 task） |

**结论：Sprint 1-5 四次 deferred 的「巨型文件拆分」已被游离 commit 收割（既成事实）。Sprint 6 聚焦验证这些改动的稳定性 + bug fix 模式的同类防御（OQ 驱动）。**

## 4. Verification Fidelity（Sprint 5 commit gate 覆盖 + 游离 commit 状态）

> 方法：权威 `git log`（H6 按扩展名 .go）。Sprint 5 源码 commit + 游离 commit 分别评估。

### Sprint 5 源码 commit（0e673fe7..722b123b 范围内的源码改动）

| Sprint 5 源码 commit | 触及源码文件 | plan target_files | 覆盖 gate | 门禁？ |
|----------------------|------------|-------------------|----------|--------|
| 0e673fe7 (T1) | 108 测试删除 + 3 helper + http.go 无 | T1 target ✅ | go_test+vet+deletion_protection+ci_gate_ebpf_test(L2 retry) | ✅ gated |
| 1d1021eb (T2) | component/sniffing/http.go | T2=http.go ✅ | go_test+cpu_profile+memprofile | ✅ gated |
| d3e5c4a2 (T3) | component/sniffing/benchmark_test.go | T3=benchmark_test.go ✅ | go_test+h8_deadline_sync | ✅ gated |
| 722b123b (L2 fix) | control/bpf_bug_verification_test.go | L2 retry（ISSUE-1 修复） | ci_gate_ebpf_test EXIT=0 | ✅ gated |

**Sprint 5 fidelity：源码改动 100% gated，0% ungated（延续 Sprint 1-5 记录）。**

### 游离 commit（722b123b..HEAD，既成事实基线）

| 维度 | 状态 | 说明 |
|------|------|------|
| gate 覆盖 | ⚠️ **部分** | go vet/test EXIT=0（已验）；race/ebpf/ebpf-test/lint/sync-check/bench **未权威验证** |
| fidelity 判定 | **既成事实基线**（非 Sprint 5 ungated） | 这 23 个 commit 不属于 Sprint 5 plan scope，是 Sprint 5 完成后的外部改动 |
| Sprint 6 处置 | **T1 补齐权威验证** | 把 race/ebpf/ebpf-test/lint/sync-check/bench 跑全，捕获回归 |

> **fidelity_risk: MEDIUM**。Sprint 5 自身 0% ungated；游离 commit 是未验证的既成事实（vet/test 过但 race/ci 未验），需 Sprint 6 T1 补齐。

## 5. Evals 回归检查（v4.1）

对 backlog 每个含 `eval` 字段、`applies_to_sprints` 含 Sprint 6、`check_timing ∈ {pre-sprint, both}` 的项，读 Sprint 5 progress.md Trace Log 匹配 `eval.regression_signal`：

| ID | eval.regression_signal | Sprint 5 Trace 匹配？ | 处置 |
|----|------------------------|----------------------|------|
| H1 | `ci_gate.*ignored` | ❌ 未命中：S5 gate 标 runs，QA 实跑（L2 retry 后 EXIT=0） | eval 通过 ✅ |
| H3 | `EXIT=FAIL` | ⚠️ 部分命中：ci_gate_ebpf_test 首跑 FAIL，但 L2 retry 修复后 PASS | eval 通过（L2 retry 机制生效） ✅ |
| H5 | `harness.*allocs.*flat=0` | ❌ 未命中：memprofile Extended 1 alloc inherent / NoHost 0 | eval 通过 ✅ |
| H7 | `cpu flat no improvement` | ❌ 未命中：bytes.Index cum 57.92%→8.66% | eval 通过 ✅ |
| H8 | `deadline-sync 路径未激活` | ❌ 未命中：readStreamOnceWithReadDeadline 出现 / async 消除 | eval 通过 ✅（首次应用即验证） |

**结论：H1/H3/H5/H7/H8 eval 全通过。H3 的 ci_gate FAIL 被 L2 retry 修复（机制有效，非 eval 失效）。Sprint 6 持续应用 H1/H3/H5/H7/H8。**

## 6. backlog 应用清单（Sprint 6）

| Item | Apply in S6? | 如何应用 | 应用记录 |
|------|---|---|---|
| H1 | yes | T1 补跑 make ebpf-test 实跑不 ignored | ✅ applied（plan gates ci_gate_ebpf_test target=pass） |
| H3 | yes | 全程 tmp/sprint6-*.sh 脚本化 | ✅ applied（drift §0 探针 + plan gates） |
| H4 | yes | T1 target 含拆分后的关联文件 | ✅ applied |
| H5 | yes | T1 bench 非回归用 memprofile 旁证 | ✅ applied |
| H6 | yes | fidelity 按扩展名（drift §4 按 .go git-log） | ✅ applied |
| H7 | conditional | Sprint 6 非 CPU 优化主题，但验证 race 时关注 GC 维度 | ⚠️ 旁证（非决定性） |
| H8 | yes | T1 bench 非回归用 deadline-sync bench 数据 | ✅ applied |
| H9 | yes | Sprint 6 单 task，topology=sequential（无重叠风险） | ✅ applied |
| **H10** | **deferred** | Sprint 6 不涉文件删除 → 适用条件不满足 | 🟡 deferred |
