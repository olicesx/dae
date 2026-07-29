---
sprint: 2
check_type: cross-sprint-drift
run_by: Remy
run_at: 2026-07-29
prev_sprint: 1
verification_fidelity_method: manual-git-log
verification_fidelity_script_note: >
  verification-fidelity-check.ps1 不存在（file_search 全仓无命中）。
  降级：手动 git log --stat 核对 Sprint 1 各 commit 触及文件是否被 gate 覆盖（见下）。
  记于本文件 + progress.md Trace Log。
---

# Sprint 2 — Cross-Sprint Drift Check

> 第 2 个 Sprint 强制执行。来源：EvoClaw Drift 章节 + orchestrator L4 Hill Climbing。
> 输入：Sprint 1 `runtime-context.md` / `hill-climbing.md` / `progress.md` + `/memories/repo/harness-backlog.md` + `/memories/repo/lessons-learned.md`。

## 1. Context Drift（工具链/环境漂移）

| 项 | Sprint 1 基线 | Sprint 2 实测 | 漂移？ |
|----|--------------|--------------|--------|
| Go | go1.26.0 linux/amd64 | go1.26.0 linux/amd64 | ❌ 无 |
| clang | 18.1.3 (Ubuntu) | 18.1.3 (Ubuntu) | ❌ 无 |
| kernel | 6.18.33.2-microsoft-standard-WSL2 | 6.18.33.2-microsoft-standard-WSL2 | ❌ 无 |
| `.build_tags` | `trace` | `trace` | ❌ 无 |
| 分支 / 工作树 | kdae | kdae，clean（git status --porcelain 空） | ❌ 无 |

**结论：零 Context Drift。** 环境与 Sprint 1 完全一致，benchmark / instruction-count 基线可直接对比，无需重新校准。

## 2. Error Propagation（L1-L8 逐条对照 Sprint 2 plan）

| Lesson | 陷阱 | Sprint 2 规避措施 | 规避？ |
|--------|------|------------------|--------|
| L1 | 代码已高度池化（8 处 Pool），多数"优化"是 no-op | H2 bench 驱动选文件（先证实非零 allocs/op）；Dev 动手前 grep 生产调用者 | ✅ |
| L2 | desc 点名函数可能是生产死代码（仅 test/bench） | T2/T3 排除 DnsCache_Clone/FillInto*（test-only）；Dev 须确认 sniffing/relay 目标有生产调用 | ✅ |
| L3 | daedns Router 方法跨文件，文件名误导 | T1 明确 target=client.go（非 router.go），L3 已记录 client.go 含全部 per-query buffer | ✅ |
| L4 | PackBuffer() 安全条件（同步消费） | T1 lookupType msg.Pack→PackBuffer 须满足 L4 同步消费条件；沿用 udpDNSBufPool 既有写法 | ✅ |
| L5 | replace_string 同文件多相同块需唯一锚点 | 编辑规范已写入 plan 交接（Dev 阶段） | ✅ |
| L6 | eBPF lookup 冗余分析（clang -emit-llvm DCE） | 本 Sprint 无 .c 改动，不涉及 | N/A |
| L7 | WSL 路径/PowerShell 转义陷阱（`$?`/`$()` 被吃） | H3：所有命令脚本化 tmp/*.sh 再 `wsl bash`，禁 inline `$`；本 drift check 全程脚本化 | ✅ |
| L8 | WSL2 本机可跑 make ebpf-test（非 ignored） | H1 应用：plan 标 `make ebpf-test` 为 `local: runs`（本机实跑 PASS 3.187s），不标 ignored | ✅ |

**结论：L1-L8 全部规避或 N/A，无未规避错误传播风险。**

## 3. Tech Debt（OQ4 纳入确认）

| OQ | 内容 | Sprint 2 处置 | 纳入？ |
|----|------|--------------|--------|
| OQ4 | daedns `client.go` per-query buffer 池化（sendStreamDNS req/lengthBuf/respBuf @556-571、queryHTTPS io.ReadAll @542、lookupType msg.Pack→PackBuffer @253） | **T1**：target_files=component/daedns/client.go（H4 关联文件） | ✅ 纳入 |

**结论：OQ4 已纳入 Sprint 2 作为 T1（用户指定 + H4 target_files 扩展）。** 其余 Sprint 1 OQ1-OQ3 已在 Sprint 1 闭环（OQ2 已确认、OQ1/OQ3 为环境记录非债务）。

## 4. Verification Fidelity（Sprint 1 commit 是否全被 gate 覆盖）

> 方法：手动 `git log --stat`（脚本 `tmp/sprint2-env.sh`）。verification-fidelity-check.ps1 不存在 → 降级（见 frontmatter note）。

| Sprint 1 commit | 触及源码文件 | 覆盖 gate | 门禁？ |
|-----------------|------------|----------|--------|
| e2e78563 (A1) | control/dns_control.go | go_test(control)+race+vet+build | ✅ gated |
| 8e0c17df (A2) | control/udp_ordered_dispatcher.go, udp_reply_dispatcher.go | go_test+race+bench | ✅ gated |
| aa7a0891 (A4) | control/routing_matcher_builder.go | go_test(routing)+vet+build | ✅ gated |
| ea214acf / 80fba14a (B1/B2) | 仅 docs（tproxy.c 无源码改动=no-op） | ebpf_lint+sync-check ran（无源码可门禁） | ✅ N/A（no-op） |
| d203574c | 仅 docs | — | ✅ N/A（docs） |

**量化结论：**
- 代码 commit：3/3（A1/A2/A4）**100% 被 gate 覆盖**。
- 无任何 ungated 源码文件。
- **fidelity_risk: LOW（0% ungated）**。Sprint 1 的 no-op 率（57%）是 scope/选文件问题（H2 对症），非 fidelity 问题。

## 5. Evals 回归检查（v4.1，紧接 #6 应用 L4 之后）

对 backlog 每个含 `eval` 字段且 `applies_to_sprints` 含 Sprint 2、`check_timing ∈ {pre-sprint, both}` 的 Pending 项，读 Sprint 1 progress.md Trace Log 匹配 `eval.regression_signal`：

| ID | eval.regression_signal | Sprint 1 Trace 匹配？ | 处置 |
|----|------------------------|----------------------|------|
| H1 | `ci_gate.*ignored` | ✅ 命中：progress `ebpf_test_ci: ignored`（且 L8 QA 实跑通过） | **eval REGRESSION: H1** → plan.md 显式写 H1 验证方式 |
| H2 | `no_op_tasks.*[4-9]/` | ✅ 命中：progress `no_op_tasks: 4（A3/A5/B1/B2）` + hill-climbing `4/7` | **eval REGRESSION: H2** → plan.md 显式写 H2 验证方式 |
| H3 | `EXIT_(BUILD|TEST)=True` | ❌ 未命中：Sprint 1 gate 全 PASS，无 EXIT_=True | eval 通过，记入 done.md「Evals 回归结果」 |
| H4 | （无 eval 字段） | — | 跳过 |

**结论：H1/H2 命中回归信号**（确认 Sprint 1 存在这两类问题，正是改进项要修复的）→ plan.md 第 verifiable_gates 段必须显式写「如何验证改进生效」（非仅"应用改进"）。**H3 eval 通过**（脚本化已全程落实）。

## 6. 应用 L4 改进项汇总

| ID | 应用方式 | 应用记录 |
|----|---------|---------|
| H1 | 实跑 `make ebpf-test`(PASS 3.187s) + `make ebpf`(EXIT=0) + build(EXIT=0)；plan 标 `make ebpf-test: local=runs` | ✅ applied（见 plan verifiable_gates） |
| H2 | 实跑 `go test -tags=trace -bench -benchmem -benchtime=200ms`；按 allocs/op 实测排序选 T2/T3 | ✅ applied（见 plan task DAG + bench 基线表） |
| H3 | 全程 tmp/*.sh 脚本化（sprint2-env.sh/bench-scan.sh/sprint2-bench2.sh），禁 inline `$` | ✅ applied |
| H4 | T1 target_files = client.go（router.go 的同模块同 pool 关联文件） | ✅ applied |

> harness-backlog.md「应用记录」表已同步标 ✅ applied。

## 7. Drift Check 总结

| 检查项 | 结论 | 风险 |
|--------|------|------|
| Context Drift | 零漂移 | 无 |
| Error Propagation | L1-L8 全规避/N/A | 无 |
| Tech Debt | OQ4 纳入（T1） | 无 |
| Verification Fidelity | 100% 代码 commit gated（手动，脚本降级） | LOW（0% ungated） |

**Sprint 2 plan 可放行。**
