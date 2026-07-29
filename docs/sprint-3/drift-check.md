---
sprint: 3
check_type: cross-sprint-drift
run_by: Remy
run_at: 2026-07-29
prev_sprint: 2
sprint_theme: "Memory optimization via H5 (bench + memprofile dual verification)"
verification_fidelity_method: manual-git-log
verification_fidelity_script_note: >
  verification-fidelity-check.ps1 ran → returned `PASS no_source_changes`.
  This is a FALSE negative on detection: the script keys source-file detection on
  a `src/`-style layout (Rust/sync_watcher origin, see script header). dae is Go
  with no `src/` prefix, so the script's heuristic found zero "source" changes
  even though Sprint 2 touched component/daedns/client.go and
  component/sniffing/internal/quicutils/relocation.go. The PASS *conclusion*
  (all source commits gated) happens to be correct for Sprint 2, but for the
  wrong reason. Recorded as H6 (harness backlog) — script needs Go-aware source
  detection. Manual git-log cross-check used as authoritative (see §4).
---

# Sprint 3 — Cross-Sprint Drift Check

> 第 3 个 Sprint 强制执行。来源：EvoClaw Drift 章节 + orchestrator L4 Hill Climbing。
> 输入：Sprint 2 `runtime-context.md` / `hill-climbing.md` / `progress.md`（Sprint+1 候选为空）+ `/memories/repo/harness-backlog.md`（H5 pending）+ `/memories/repo/lessons-learned.md`（L1-L9）。

## 1. Context Drift（工具链/环境漂移）

探针：`tmp/sprint3-env.sh`（2026-07-29）。

| 项 | Sprint 1/2 基线 | Sprint 3 实测 | 漂移？ |
|----|----------------|--------------|--------|
| Go | go1.26.0 linux/amd64 | go1.26.0 linux/amd64 | ❌ 无 |
| clang | 18.1.3 (Ubuntu) | 18.1.3 (Ubuntu) | ❌ 无 |
| kernel | 6.18.33.2-microsoft-standard-WSL2 | 6.18.33.2-microsoft-standard-WSL2 | ❌ 无 |
| bpftool | /usr/sbin/bpftool | /usr/sbin/bpftool | ❌ 无 |
| `.build_tags` | `trace` | `trace` | ❌ 无 |
| 分支 / 工作树 | kdae | kdae，clean（git status --porcelain 空） | ❌ 无 |

**结论：零 Context Drift。** 连续 3 个 Sprint 环境一致，benchmark/instruction-count 基线可直接横比。

## 2. Error Propagation（L1-L9 逐条对照 Sprint 3 plan）

| Lesson | 陷阱 | Sprint 3 规避 | 规避？ |
|--------|------|--------------|--------|
| L1 | 代码已高度池化，多数"优化"是 no-op | Sprint 3 核心 = H5 memprofile 区分生产 vs harness；只对生产 flat alloc 设 task | ✅ |
| L2 | desc 点名函数可能是生产死代码 | T1 target `isConnectionRefused`/`errStrLower` 经 grep 确认生产调用（UDP 读循环 ICMP-refused 处理），非 test-only | ✅ |
| L3 | 跨文件方法命名误导 | T1 单文件 control/udp_endpoint_pool.go，errStrLower/registerEndpoint/createEndpointLocked/isConnectionRefused 全在同文件 | ✅ |
| L4 | PackBuffer 同步消费 | 本 Sprint 不涉及 Pack 路径 | N/A |
| L5 | replace_string 同文件多相同块 | T1 编辑交接（Dev 阶段） | ✅ |
| L6 | eBPF lookup 冗余（clang DCE） | 本 Sprint 无 .c 改动 | N/A |
| L7 | WSL 路径/PowerShell 转义 | H3：全程 tmp/*.sh → `wsl bash`；本次 drift 全程脚本化（sprint3-env/fidelity/survey/mem2.sh） | ✅ |
| L8 | WSL2 可跑 make ebpf-test | 延续 Sprint 2：gate 标 `local: runs` | ✅ |
| **L9** | **bench allocs ≠ 生产 allocs（memprofile 区分）** | **Sprint 3 核心 = L9 的方法论固化进 H5**：每个候选热点 memprofile flat 分类，harness 噪声不得设 task | ✅✅ |

**结论：L1-L9 全部规避，L9（memprofile 区分）成为本 Sprint 方法论核心。**

## 3. Tech Debt（Sprint 2 遗留 OQ / Sprint+1 候选）

| 来源 | 内容 | Sprint 3 处置 |
|------|------|--------------|
| Sprint 2 progress「Sprint+1 候选」 | （空）— QA 未记录功能 backlog | 无遗留 |
| Sprint 2 hill-climbing「Sprint+1 候选」 | sniffing QUIC 剩余非密码学分配（ExtractCryptoFrameOffset 经 s.quicCryptas 跨调用存活、NewLinearLocator 装箱入 Locator 接口）需更深重构（接口/生命周期） | **本 Sprint memprofile 复核**：见 §5 B 项，确认为生命周期边界，**仍排除**（用户硬约束：超语义等价边界 → Sprint+1） |
| Sprint 1 OQ4 | daedns client.go | Sprint 2 T1 已闭环 |

**结论：无新 OQ 纳入。Sprint 2 的 sniffing 生命周期候选项经 memprofile 复核确认仍超边界，记 Sprint+1（非本 Sprint）。**

## 4. Verification Fidelity（Sprint 2 commit 是否全被 gate 覆盖）

> 方法：`tmp/sprint3-fidelity.sh` 手动 `git show --stat d203574c..HEAD`。脚本 `verification-fidelity-check.ps1` 返回 `PASS no_source_changes` 为假阴性（见 frontmatter note / H6）。

| Sprint 2 commit | 触及源码文件 | plan target_files | 覆盖 gate | 门禁？ |
|-----------------|------------|-------------------|----------|--------|
| 4c1de816 (T1) | component/daedns/client.go | T1=component/daedns/client.go ✅ | go_test(daedns)+race+vet+build | ✅ gated |
| c1ab617d (T3) | component/sniffing/internal/quicutils/relocation.go | T3=component/sniffing/*.go（glob 命中）✅ | go_test(sniffing)+race+vet+build | ✅ gated |
| 26bc9f61 | docs/sprint-2/progress.md | — | docs（无源码） | ✅ N/A |
| 2cd90056 | PROJECT_BRIEF.md + docs/** | — | docs（无源码） | ✅ N/A |

**量化结论：**
- 源码 commit：2/2（T1 client.go / T3 relocation.go）**100% 在 plan target_files 内且被 gate 覆盖**。
- T2 为 no-op（无 commit，memprofile 证据），不计。
- **fidelity_risk: LOW（0% ungated）**。与 Sprint 1 一致（Sprint 1 也是 100% gated）。fidelity 持续干净，no-op 率问题是 scope/选文件（H2/H5 对症）。

## 5. Evals 回归检查（v4.1）

对 backlog 每个含 `eval` 字段、`applies_to_sprints` 含 Sprint 3、`check_timing ∈ {pre-sprint, both}` 的项，读 Sprint 2 progress.md Trace Log 匹配 `eval.regression_signal`：

| ID | eval.regression_signal | Sprint 2 Trace 匹配？ | 处置 |
|----|------------------------|----------------------|------|
| H1 | `ci_gate.*ignored` | ❌ 未命中：Sprint 2 plan 标 `local: runs`（非 ignored），实跑 PASS | eval 通过 ✅（H1 改进持续生效） |
| H2 | `no_op_tasks.*[4-9]/` | ❌ 未命中：Sprint 2 no_op=1/3（33%，< 4） | eval 通过 ✅（H2 改进持续生效） |
| H3 | `EXIT_(BUILD\|TEST)=True` | ❌ 未命中：Sprint 2 gate 全 PASS | eval 通过 ✅ |
| H5 | `harness.*allocs.*flat=0` | ❌ 未命中：H5 为新项（Sprint 2 产出），无 Sprint 2 前置回归信号 | 新项首次应用，本 plan 显式写 H5 验证方式（见 plan.md §eval） |

**结论：H1/H2/H3 eval 全通过（改进持续生效），H5 为新项首次应用。无 eval REGRESSION。**

## 6. H5 应用（本 Sprint 核心）

H5 = bench + memprofile 双验证（H2 增强）。**Producer 阶段即执行**（非 Dev 阶段）：
1. 全量 bench 调研（`tmp/sprint3-survey.sh`，-benchtime=300ms）→ 列出所有 allocs/op>0 热点。
2. 对每个候选跑单包 `-memprofile`（`tmp/sprint3-mem2.sh`）→ pprof flat% 分类为生产 vs harness。
3. harness 噪声（flat 在 testing/bytes.NewReader/net.Listen）**不得设 task**（H5 硬约束）。

应用方式见 plan.md task DAG（每 task 标注 memprofile flat% 证据）+ runtime-context.md §H5 分类表。应用后 backlog「应用记录」标 H5 ✅ applied (Sprint 3)。

**新增 H6（drift 过程发现）**：verification-fidelity-check.ps1 假设 `src/` 布局，Go 项目假阴性 PASS。记入 backlog Pending（见 harness-backlog.md）。
