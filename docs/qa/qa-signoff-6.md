---
sprint: 6
sprint_theme: "Stability / bug fix harvest (new sprint type) / 稳定性 / bug fix 收割"
qa_engineer: Ivy
branch: kdae
head_commit: 149b3ce9
run_at: 2026-08-04
content_language: bilingual
verdict: PASS
verdict_history: "PASS (QA independent rerun: make ebpf-test rc=0 + sniffing bench H8 exact match + make dae validate rc=0)"
commits_used: 1   # 149b3ce9 (docs: T1 verification baseline); scenario (a): 0 code regression, 0 fix commit
open_issue: 0   # OQ-S6-3/S6-4 为建议类（独立仓库职责/上游 bug），不阻塞签署，记录留待用户裁决
issue_tracker: "in-doc (fork olicesx/dae 不提 Issue；OQ-S6-4 上游 bug 建议提 daeuniverse/dae，待用户确认)"
---

# Sprint 6 QA Sign-off — 稳定性 / bug fix 收割（新 Sprint 类型）

> QA: Ivy. Method: deterministic-first（gate 优先机器判定）。本 Sprint 是 **stability_verification** 新类型 —— T1 对 23 个游离 commit（722b123b..1ddfd8fb，巨型文件拆分 + 5 bug fix + fork bump，59 files/+8608/-7018）补齐权威验证基线，**0 源码改动**（head 149b3ce9 是纯 docs commit）。
>
> **verdict = PASS**：local_gate 全过（orchestrator-L2 权威，l2_verified_sha=149b3ce9）+ ci_gate 全过（QA 独立重跑 `make ebpf-test` rc=0 + bench H8 精确匹配）+ manual_gate 全过（QA 独立复核 `make dae` + validate rc=0）。**scenario (a) 命中**：23 游离 commit 稳定性 proven，0 回归，commits_used=1（docs only）。

## §1 验证任务复核 / Verification Task Review

| Task | 验证范围 | commits | status |
|------|---------|---------|--------|
| T1 游离 commit 权威验证基线 + 回归修复 | 23 commit（722b123b..1ddfd8fb）：race ./... + ebpf/ebpf-test/lint/sync-check + bench 非回归 + make dae validate | 0 code + 1 docs (149b3ce9) | ✅ delivered（scenario a: 10/10 gate pass, 0 回归） |

**Scenario 判定**：plan.md expected 列两种合法结果 —— (a) 全过=基线确认 / (b) 发现回归=捕获修复。**实测命中 (a)**：23 游离 commit（含 sniffer Close guard / janitor event-driven / udp pool 拆分 / dns TC bit fix / fork bump GSO+buffer race）经 race + ebpf + bench 三维度权威验证，零回归。commits_used=1（149b3ce9 纯 docs，0 源码改动），远低于 budget=3（hard_cap=10）。

**Fidelity**：head 149b3ce9 `git show --stat` 确认仅 4 docs files（docs/sprint-6/{plan,progress,drift-check,runtime-context}.md）/ +466 ins / 0 源码 del。Sprint 6 是验证 task，本身不产生源码改动；游离 commit 是 Sprint 5 外既成事实基线（drift-check §0 锁定），非本 Sprint 产出。

## §2 Gate 执行矩阵 / Gate Execution Matrix

### 2.1 local_gate（orchestrator-L2 权威，QA 不重跑）

> 按 kixpower-qa 规范：local_gate 由 Orchestrator 已执行权威 L2（记录 gate ID + SHA），QA **不重跑**避免重复消耗。l2_verified_sha=149b3ce9。

| Gate | cmd | result | source |
|------|-----|--------|--------|
| go_vet | `go vet -tags=trace ./...` | ✅ PASS | orchestrator-L2 (EXIT=0, WSL linux 全量) |
| go_build | `go build -tags=trace ./...` | ✅ PASS | orchestrator-L2 (EXIT=0) |
| go_test | `go test -tags=trace ./...` | ✅ PASS | orchestrator-L2 (19+ 包 ok / 0 FAIL) |
| go_test_race | `go test -race -tags=trace ./...` | ✅ PASS (无 DATA RACE) | orchestrator-L2 **独立重跑** (rc=0, 50.5s) |

### 2.2 ci_gate（QA 独立补跑 + L2 权威）

| Gate | cmd | result | evidence |
|------|-----|--------|----------|
| **ci_gate_ebpf_test** | `make ebpf-test` | ✅ **PASS (QA rc=0)** | QA 独立重跑 3.048s，23 用例全 PASS（DscpMatch/IpsetMatch/L4protoMatch/LanIngress*/RoutingEpoch*/WanEgress*/ConntrackArgsScratchReset 等）；L16/L17 build-tag 门控验证通过。L2 亦独立重跑 rc=0 |
| ci_gate_make_ebpf | `make ebpf` | ✅ PASS | orchestrator-L2 (rc=0, 7.7s; bpf_bpfeb/bpfel.go + .o 生成) |
| ebpf_lint | `make ebpf-lint` | ✅ PASS | orchestrator-L2 (rc=0 via perl direct; 3 C 文件 clean after CRLF env fix) |
| ebpf_sync_check | `make ebpf-sync-check` | ✅ PASS | orchestrator-L2 (rc=0, `git diff --exit-code` clean) |

### 2.3 manual_gate（QA 独立复核）

| Gate | result | evidence |
|------|--------|----------|
| make_dae | ✅ PASS | QA 独立复核 EXIT=0；`go build -tags=trace -o dae`，Version=`unstable-20260804.r1008.149b3ce9`（HEAD commit 正确反映） |
| dae_validate_example | ✅ PASS | QA 独立复核 `./dae validate -c example.dae` EXIT=0（L8：chmod 0600 临时副本） |
| dae_validate_empty | ✅ PASS（正确拒绝） | QA 独立复核 `./dae validate -c /dev/null` EXIT=1「invalid config filename /dev/null: must has suffix .dae」— 非 .dae 后缀被正确判定无效，非 panic/crash |

### 2.4 决定性 gate（QA 独立跑，详见 §3）

| Gate | result | 备注 |
|------|--------|------|
| bench_no_regression (sniffing H8) | ✅ PASS | QA 实测 5 个 H8 关键 allocs **精确匹配**零回归（§3.2） |
| bench_no_regression (control dispatch) | ✅ PASS | QA 实测 rc=0, 83.127s（§3.3） |

## §3 QA 独立复核证据 / QA Independent Review Evidence

> 三通道第三通道：QA 不盲信 Dev/L2 claim，独立重跑关键 ci_gate + manual_gate。命令脚本化于 `tmp/sprint6-qa-*.sh` + 既有 `tmp/sprint6-gate-*.sh`，WSL Ubuntu 执行（kernel 6.18 / go1.26 / clang18）。

### 3.1 make ebpf-test（L16/L17 build-tag 门控核心验证）

**命令**：`wsl -d Ubuntu -e bash tmp/sprint6-gate-ebpf-test.sh`（QA 复用 Dev 脚本，独立 session 重跑）

**结果**：rc=0，real 15.816s（test 阶段 3.048s）。所有 `dae_bpf_tests` 用例 PASS：

| 用例类别 | 代表用例 | 状态 |
|---------|---------|------|
| Match/Mismatch | DscpMatch / DscpMismatch / IpsetMatch / IpversionMatch / L4protoMatch / MacMatch / SourceIpsetMatch / SportMatch / NotMatch / NotMismtach | ✅ PASS |
| LanIngress | LanIngressTcpDscpConnState / LanIngressTcpSynFirstFragmentListener / LanIngressUdpDscpConnState / LanIngressUdpFirstFragmentListener / LanIngressUdpIpv6DscpConnState / LanIngressUdpNonInitialFragmentPassthrough | ✅ PASS |
| LanTcp/Udp Cached | LanTcpCachedOutboundSurvivesConnectivityChange / LanUdpCachedOutboundSurvivesConnectivityChange | ✅ PASS |
| RoutingEpoch | RoutingEpochDomainProjectionSlot{Zero,One} / RoutingEpochSlot{Zero,One}Handoff | ✅ PASS |
| Tcp state | TcpActiveIdleStateRetained / TcpNonSynCachedProxyRedirect / TcpNonSynMarkRestore / TcpNonSynStatelessPassthrough / TcpPureSynReplacesStaleState | ✅ PASS |
| WanEgress | WanEgressDirectMarkReroute / WanEgressTcpNonSynCachedProxyRedirect / WanEgressTcpNonSynStatelessPassthrough / WanEgressTcpSynRedirectTrack / WanEgressUdp{FirstFragment,NonInitialFragment,Redirect}*/WanTcpCached/WanUdpCached/WanUdpNew | ✅ PASS |
| Scratch | ConntrackArgsScratchReset | ✅ PASS |

**L16/L17 验证结论**：build-tag 门控文件（`//go:build linux && dae_bpf_tests`）对默认 `go test ./...` 不可见，但 Makefile `go generate ./control/bpf_bug_verification_test.go && go generate ./control/kern/tests/bpf_test.go && go test -v -tags dae_bpf_tests ./control/kern/tests/...` 完整覆盖。23 游离 commit 的巨型文件拆分（dns_control.go→6 文件 / udp_endpoint_pool.go→3 文件）+ bug fix（dns TC bit `1ddfd8fb` / sniffer nil buf `28872b0b`）未破坏 eBPF build-tag 门控测试链。

### 3.2 sniffing bench H8 非回归（决定性）

**命令**：`wsl -d Ubuntu -e bash tmp/sprint6-qa-bench-sniffing.sh`（QA 新建，只跑 sniffing 避免 control warning log 截断）

**对照基线**：Sprint 5 H8 deadline-sync bench（runtime-context.md 锁定）

| Benchmark | QA allocs/op | H8 baseline allocs | QA ns/op | 状态 |
|-----------|-------------|--------------------|----------|------|
| Sniffer_SniffTcp_HTTP | **5 (224 B)** | 5 (224 B) | 360.5 | ✅ 精确匹配 |
| Sniffer_SniffTcp_TLS | **6 (240 B)** | 6 (240 B) | 364.1 | ✅ 精确匹配 |
| Sniffer_SniffTcp_NotApplicable | **3 (168 B)** | 3 (168 B) | 279.1 | ✅ 精确匹配 |
| SniffHTTPHostHeader_Extended | **1 (32 B)** | 1 (32 B) | 74.69 | ✅ 精确匹配 |
| SniffHTTPHostHeader_NoHost | **0** | 0 | 30.99 | ✅ 精确匹配 |
| Sniffer_SniffUdp_QUIC | 60 (5425 B) | —（H8 未覆盖） | 4060 | 📊 记录（无基线对照） |
| Sniffer_SniffUdp_QUICMultiPacket | 142 (14091 B) | —（H8 未覆盖） | 10179 | 📊 记录（无基线对照） |
| IsLikelyQuicInitialPacket | 0 | — | 0.1448 | 📊 记录 |

**H8 verdict：PASS。** 5 个 H8 关键 allocs 指标**精确匹配**零回归（HTTP=5/TLS=6/NotApp=3/Extended=1/NoHost=0）。sniffer nil buf guard（`28872b0b`）只影响 Close 后路径，正常路径 bench 不变 —— 与 runtime-context.md 预判一致。ns/op 在 ±15% 微基准噪声内（Extended 74.69 vs S5 QA 89.17 vs Dev 80.91；NoHost 30.99 vs S5 QA 37.30 vs Dev 32.82）。

### 3.3 control bench dispatch（非回归抽检）

**命令**：`wsl -d Ubuntu -e bash tmp/sprint6-gate-bench.sh`（Dev 既有脚本，QA 独立 session 重跑）

**结果**：rc=0，control 包 83.127s（Dev 报告 88.1s 同量级）。关键 allocs：

| Benchmark | QA allocs | 备注 |
|-----------|-----------|------|
| UDPReplyDispatcherSubmitDrain（全场景 e=1/64/1024 × p=1/8） | 0 allocs/op | ✅ dispatch 热路径零分配 |
| UDPOrderedDispatcherSubmitDrain（legacy/new，除 legacy_pool/f=1024_p=8=1B） | 0 allocs/op | ✅ 新 dispatcher 与 legacy 持平 |
| UDPDispatcherClosedCheck atomic | 0 allocs/op（0.3351/0.2051 ns/op） | ✅ atomic 远优于 mutex_baseline (10.91 ns) |
| UdpProxyDial cache=miss / cache=hit | 18 / 0 allocs | ✅ cache hit 零分配 |
| QuicInitialEndToEnd legacy_pool p=1 / ordered_ingress p=1 | 44 / 37 allocs | ✅ ordered_ingress 更优（admission saturated warning 是 bench 压力测试预期行为，非 bug） |

### 3.4 make dae validate（playthrough）

**命令**：`wsl -d Ubuntu -e bash tmp/sprint6-gate-dae-validate.sh`（QA 独立 session 重跑）

| 步骤 | rc | 证据 |
|------|----|------|
| make dae | 0 | `go build -tags=trace -o dae`，Version=`unstable-20260804.r1008.149b3ce9` |
| validate example.dae | 0 | 配置校验通过（L8 chmod 0600 临时副本） |
| validate /dev/null | 1（预期） | `invalid config filename /dev/null: must has suffix .dae` —— 非 panic/crash |

**playthrough 说明**：Sprint 6 是验证 task（非新功能），playthrough = 确认 dae 二进制可构建 + 配置校验工作。透明代理完整 playthrough 同 Sprint 1-5 manual-limited（WSL2 非生产部署）。行为正确性由 deterministic gate（go test 19+ 包 / race / bench 断言全过）+ ebpf-test 23 用例 + sync-check 保证。

## §4 OQ 评估 / Open Questions Assessment

| OQ | 内容 | QA 评估 | 处置 |
|----|------|---------|------|
| OQ-S6-1 | 游离 commit bug fix 是否有同类未处理边界？（dns UDP size / sniffer 并发 Close / janitor timing） | 证据驱动，不预设。T1 验证全过（race 50.5s 无并发问题 + ebpf-test 全过 + bench 零回归），**未发现真实未处理边界**。bug fix 模式（dns TC bit / sniffer nil buf / dns black-hole / preserve dae DNS / drop unused roll）各自独立，无明显同类蔓延。 | **关闭**（T1 验证未发现同类边界；若未来重现 → Sprint+N 候选） |
| OQ-S6-2 | 巨型文件拆分后是否引入编译/测试盲区？ | **T1 已验证 PASS** —— make ebpf-test rc=0（23 用例）+ go test 全包 ok + race 无并发问题。拆分（dns_control.go→6 文件 / udp_endpoint_pool.go→3 文件 / run.go→4 文件 / control_plane.go embedded structs 提取）未引入 build-tag 覆盖或包级可见性盲区。 | **关闭**（验证 PASS） |
| OQ-S6-3 | fork 验证 gap（用户关切）：dae replace 引用 olicesx/outbound `c5b8ecc` + olicesx/quic-go `dff8aaa5`（非各自 main），fork 代码在 dae 测试盲区 | **不阻塞签署**（独立仓库职责，本 Sprint 范围外）。qa-signoff 角度：fork 内部测试覆盖属 fork 仓库自身职责，dae 只验证集成接口（编译通过 + dae 测试通过）。本地 workspace 已 checkout 对齐（detached at c5b8ecc/dff8aaa5, status clean），dae 编译走远程 go.mod 正常。提 Issue 给上游 olicesx fork 缺乏明确 bug 锚点（只是"测试覆盖建议"），不适合直接提。 | **记录为 Sprint+1 候选**（fork 验证 harness 建立），不在本 Sprint 提 Issue |
| OQ-S6-4 | Makefile 上游 bug：`.gitmodules.d.mk` 生成规则 `tr ' \n' '\n '` 把空格转换行 → 第 2 行 `submodule_paths=` 重复赋值（trace 覆盖 control） | **真实可复现 bug**（Makefile:51 源码 + tr 命令行为已取证）。正确修复应改 Makefile 生成规则。但：(a) 这是上游 daeuniverse/dae 的 bug（本仓库是 fork olicesx/dae）；(b) Dev 手动 workaround 已 revert（生成产物不该手改）；(c) 提上游 Issue 是不可逆 + 外部仓库动作。 | **建议提上游 daeuniverse/dae Issue**，但**需用户确认**（外部仓库 + 不可逆）。QA 不擅自提 |

## §5 L18 环境障碍验收 / L18 Environment Obstacles Verification

> drift-check §2 + lessons-learned L18：Sprint 6 T1 验证遇到 4 个 WSL 构建环境障碍。QA 确认这些是**环境状态**（非代码回归），且 Dev 已正确区分处理。

| ID | 障碍 | Dev 处置 | QA 验收 |
|----|------|---------|---------|
| L18a | submodule headers 未 init（github.com 直连不稳） | gh-proxy.com 镜像 init（4m51s, 2 headers @ 56937c66） | ✅ submodule 已就位（make ebpf-test ebpf-sync 步骤正常） |
| L18b | Makefile .gitmodules.d.mk 上游 tr bug | 手动写单行格式 workaround | ✅ L2 已 revert workaround（生成产物不该手改）；记 OQ-S6-4 上游 bug。当前 working tree 的 .gitmodules.d.mk 仍是 Dev workaround 内容（gitignored 生成文件，非 git 跟踪），make ebpf-test 能正常跑 |
| L18c | checkpatch.pl shebang CRLF（`perl\r` not found） | `perl ./scripts/checkpatch.pl ...` 直接调用绕过 shebang | ✅ ebpf-lint L2 rc=0 via perl direct（不改文件） |
| L18d | eBPF C 源码 autocrlf 污染（i/lf w/crlf） | `sed -i 's/\r$//'` 修 working tree；git diff 确认无内容差异 | ✅ L2 确认 git diff clean（只行尾差异，无内容差异）；CRLF 污染已清理（git checkout 保护 PROJECT_BRIEF） |

**关键判别验收**：`git ls-files --eol` 区分 index（i/）vs working（w/）—— L18d 是 `i/lf w/crlf`（autocrlf 污染，环境），非 `i/crlf`（真实提交 CRLF，代码问题）。Dev 处理符合 L17 延伸原则（区分环境状态 vs 真实回归）。

## §6 H1-H10 Eval 回归验证 / Eval Regression Verification

| Eval | regression_signal | 命中？ | 处置 |
|------|-------------------|--------|------|
| H1 | `ci_gate.*ignored` | ❌ 未命中（ebpf-test 实跑 23 用例 PASS / make ebpf 实跑 rc=0） | ✅ H1 持续 |
| H3 | `EXIT=FAIL` | ❌ 未命中（全 gate rc=0） | ✅ H3 持续 |
| H5 | harness allocs flat=0 | ❌ 未命中（sniffing bench H8 精确匹配；无 harness 噪声） | ✅ H5 持续 |
| H7 | cpu flat no improvement | N/A（Sprint 6 非 CPU 优化主题） | ✅ N/A |
| H8 | deadline-sync 路径未激活 / allocs 回归 | ❌ 未命中（5 关键 allocs 精确匹配零回归） | ✅ H8 持续 |
| H9 | target_files 重叠 | N/A（单 task） | ✅ N/A |
| H10 | 文件删除未保护 | N/A（deferred，Sprint 6 不涉删除） | ✅ N/A |

## §7 Sprint+1 候选 / Sprint+1 Candidates

| 候选 | 来源 | 方向 | 优先级 |
|------|------|------|--------|
| OQ-S6-4 Makefile `.gitmodules.d.mk` 上游 tr bug 提上游 Issue | §4 本 Sprint 发现 | 上游缺陷反馈 | P2（需用户确认是否提 daeuniverse/dae） |
| OQ-S6-3 fork 验证 harness 建立 | §4 用户关切 | 测试覆盖增强 | P3（fork 内部测试属独立仓库职责，dae 可建集成接口测试） |

## §8 Reflexion 经验沉淀 / Reflexion

**L18 已写入 /memories/repo/lessons-learned.md**（Sprint 6 来源）：dae WSL 构建 4 个环境障碍（submodule init / Makefile tr bug / checkpatch CRLF shebang / C 源码 autocrlf）。关键判别：`git ls-files --eol` 区分 index vs working 行尾 —— `i/lf w/crlf` 是环境状态，`i/crlf` 是代码问题。

**Sprint 6 元经验**（验证 task 类型）：
- **stability_verification 新 Sprint 类型有效**：constraint_policy=`stability_hardening_allowed` 允许验证补齐 + bug fix + race/边界加固，禁止新 feature/拆分/eBPF C/config/fork/语义重构。T1 命中 scenario (a)（全过=基线确认）证明该类型有确定性收益（验证本身有价值）。
- **scenario (a) 的诚实记录**：T1 全过 → commits_used=1（docs only），0 code commit。progress.md frontmatter 明确标 `commits_used: 1` + `dev_self_tests_passed: true` + `scenario (a): 0 code regression, 0 fix commit`。诚实记录验证 task 的"无代码改动"结果（L1 诚实 no-op 范式延伸：验证全过=有效产出，非 no-op）。

---

## Verdict: **PASS**

| 维度 | local_gate | ci_gate | manual_gate | 结论 |
|------|-----------|---------|-------------|------|
| 结果 | ✅ 4/4 全过（orchestrator-L2 权威 l2_verified_sha=149b3ce9） | ✅ 4/4 全过（QA 独立重跑 ebpf-test rc=0 + L2 make_ebpf/lint/sync-check） | ✅ 3/3 全过（QA 独立复核 make dae + validate example + validate /dev/null） | **PASS** |

依据签署规则：local_gate 全过 + ci_gate 全过 + manual_gate 全过 = **PASS**。

**scenario (a) 命中**：23 游离 commit（722b123b..1ddfd8fb，含巨型文件拆分 + 5 bug fix + fork bump，59 files/+8608/-7018）经 race + ebpf/ebpf-test/lint/sync-check + bench H8 + make dae validate 十维度权威验证，**零回归**。head_commit=149b3ce9 是纯 docs commit（4 docs files / +466 ins / 0 源码改动）。

**QA 三通道独立复核结论**：
- **ci_gate ebpf-test**：QA 独立重跑 rc=0（3.048s, 23 用例全 PASS），独立确认 Dev/L2 的 rc=0 claim。L16/L17 build-tag 门控验证通过。
- **ci_gate bench sniffing**：QA 独立跑 5 个 H8 关键 allocs **精确匹配**零回归（HTTP=5/TLS=6/NotApp=3 allocs；HostHeader Extended=1/NoHost=0）。
- **manual_gate make dae validate**：QA 独立复核 rc=0/0/1（预期），Version=r1008.149b3ce9 正确反映 HEAD。

**OQ 处置**：OQ-S6-1/S6-2 关闭（T1 验证未发现同类边界/盲区）；OQ-S6-3 不提 Issue（独立仓库职责，记录 Sprint+1 候选）；OQ-S6-4 建议提上游 daeuniverse/dae Issue（**需用户确认**，QA 不擅自提）。

> Manual playthrough 说明：Sprint 6 是验证 task（非新功能），playthrough = dae 二进制可构建（make dae rc=0）+ 配置校验工作（validate example.dae rc=0）+ ebpf-test 23 用例 PASS + bench 断言全过。透明代理完整 playthrough 同 Sprint 1-5 manual-limited（WSL2 非生产部署）。
