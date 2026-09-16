# kdae 分支说明（重构线）

> kdae 是 dae 的架构重构/性能优化分支。本文是这条线的精简总索引，
> 取代原 706 行的 sprint 逐轮记录（sprint-1..9 过程文档已随做减法移除，
> 结论沉淀在本文与 git history 中）。

## 分支概况

- 基线：daeuniverse/dae（main），Go 1.26 + eBPF C（cilium/ebpf v0.22.0）
- 主线：语义等价重构 → 生命周期/分配优化 → 架构拆分 → 做减法（当前阶段）
- 行为变更记录见 `CHANGELOGS.md` 的 Unreleased 段（sniffing_timeout、
  bootstrap_resolver 默认值、so_mark_from_dae 语义、disable_thp、路由合并语义、
  GOMAXPROCS、QUIC 拥塞控制默认值、disable_waiting_network 等）

## 重构成果（结构性）

- `control/control_plane.go` 4315 → 3252 行，拆出 parse / dns / datapath /
  dialtarget 4 个子系统文件（Sprint 8）
- `control/control_plane_core.go` 1409 → 648 行，拆出 bind / routing（Sprint 9）
- `cmd/run.go` 拆出 run_config / run_controlplane / run_reload / run_serve /
  runtime_supervisor / reload_manager
- DNS 控制器拆为 dns_controller_{bpf,cache,forwarder,handle,response,runtime}
- 拆分方法论：三通道语义验证（函数集合一致 / body diff 仅机械副产品 /
  numstat 纯删除），配合 `make ebpf-test` 与 race 测试

## 依赖（fork pin）

- `github.com/olicesx/quic-go`、`github.com/olicesx/outbound`（go.mod replace）
- fork 改动：GSO 切包、datagram 超时契约、hy2 缓冲/关闭、PacketBatchWriter、
  传输层记录合并（anytls/UoT 批写）、grpc persistent sender
- bbr3 经 outbound pin 成为「链路速率未知」的 QUIC 默认拥塞控制器（`ac33927`），
  `cc_override` 可按出站指定控制器（未知值直接报错）；测试与回退见
  `docs/zh/bbr3-experimental-testing.md`
- 两个 fork 在 2026-09 重写过历史（`ae7dee05`），此前的 commit hash 一律作废
- fork 侧验证：`scripts/fork-cross-repo-test.sh`（解析 replace pin，跑 fork 自身测试）

## 验证 gate

```bash
make ebpf-sync                       # 生成 .build_tags（被 .gitignore 收录），干净 checkout 必先执行
go vet ./... && go build -tags=$(cat .build_tags) ./...
go test -race -tags=$(cat .build_tags) -short ./control/... ./component/...
make ebpf-lint && make ebpf-sync-check
make ebpf-test                       # 真实内核，CI matrix 6.6 / 6.12
scripts/semantic-refactor-smoke.sh   # live 冒烟（子命令式，见脚本头）
```

## 做减法阶段的工具与纪律

- 删文件前必跑 `scripts/deletion-protection-scan.sh <files>`：
  build-tag 门控文件（如 `//go:build dae_bpf_tests`）对 import 分析不可见，
  但被 Makefile `go generate` / CI 引用（Sprint 5 ISSUE-1 教训）
- 已知仍被 Makefile 引用的受保护文件：`control/bpf_bug_verification_test.go`

## 2026-08-22 之后（2026-09 线）

- 减法继续：未接线的 reload-migration 链与死 handoff 所有权（`d8c6745a`）、
  可证明死掉的参数与分支（`3abf61b3`）、被取代的 test-only accessor
  （`e984cf29`）、不可达 legacy 声明（`061095d6`）
- 性能：eBPF 热路径逐包 map 操作减负（`06451485`，路由语义不变）
- 运行时：`GOMAXPROCS` 不再默认钉 1（`968893cb`，显式环境变量仍优先）；
  启动网络等待有界化并新增 `disable_waiting_network`（`dee547fa`）
- DNS：`ipversion_prefer` 在全部投递路径生效（`83da8a0e`）、IPv4-mapped UDP
  源视同同一 endpoint（`731c446b`）、as-is TC=1 逐字透传（`24234c45`）
- 路由：拒绝未知 `l4proto` / `ipversion` 操作数（`60b970f3`）；`dae validate`
  开始 dry-run DNS 请求/响应路由块（`096a3d5d`）
- 生命周期：UDP ingress close-wake 超时干净退出（`5d04fb96`）、cgroup detach
  错误带精确程序上下文（`79cb5c07`）、bpf pin 目录失败如实上报（`e53a44d6`）
- Go 1.26 现代化：`errors.AsType` 与 `go fix` 现代化（`93454d0a` / `04435759`），
  见 `docs/go-1.26-modernization.md`
- CI：全部 action 钉 40-hex SHA、最小 permissions、GOEXPERIMENT 由 Makefile
  单点拥有（`scripts/check-build-env.sh` 守卫）、BPF 测试白名单守卫；
  fork 密钥约束与全量清单见 `docs/fork-ci-secrets.md` / `docs/fork-ci-inventory.md`
- 内存观察（dae.lan，`GOGC=600` + `GOMEMLIMIT=200MB`）：启动加载足迹约
  120MB（守护进程日志自述），RSS 峰值 = 该足迹 + arena 高水位，页面随后
  惰性归还；`HeapReleased` 上升即证明回收在进行，判断泄漏要看
  `HeapAlloc` 与 `HeapReleased` 而不是 RSS 峰值

## 待决断事项（减法 backlog）

1. ~~RoutingEpoch 无条件化~~ 已完成（2026-08-22）：legacy slot-0 发布路径与
   LPM 继承机制删除，epoch 为唯一发布路径
2. ~~UDP dispatcher promote-or-delete~~ 已决断并完成（2026-08-22）：
   删除 gated 的 ordered/reply dispatcher 与整套 feature gate
   （DAE_SEMANTIC_REFACTOR_FEATURES 移除）。依据：单生产者形态下 legacy
   pool 快 4~16%；行为测试已在 Sprint 5 修剪中丢失。抢救品已落地：
   per-task panic 隔离 + pow2 上报移植进 convoy（udp_task_pool.go），
   legacy pool 的 FIFO/独立性/panic/close 测试恢复
   （udp_task_pool_order_test.go）
3. ~~run.go 内联 reload 状态机外提 + 清理序列抽函数~~ 已完成（2026-08-22）：
   546 行匿名 goroutine 外提为 cmd/run_reload_worker.go 的
   reloadWorker.run()（共享可变状态经 struct 字段，三通道验证逐行一致）；
   14 处重复的 reload 失败清理尾序列（sdnotify + progress +
   reloadActive + clearReloadPending）收敛为 reloadManager.failReloadAttempt；
   run_shutdown_test.go 丢失的 49 个状态机/纯函数单测已恢复并适配
   （shutdownAfterSignal 并入 WithHandoff、fast-exit 现在也关 netns）
4. Sprint 10 候选：dns.go / dns_controller_cache.go 拆分（先评估内聚性）
5. ~~fork 的 netproxy.PacketReceiver 推送模式接入~~ 已完成（2026-08-22）：
   推送模式重接到 legacy replyCh 路径（udp_endpoint_watcher.go 的
   startTransportReceiver/handleReceivedPacket + Close 排空），不再依赖
   已删除的 reply dispatcher。direct 出站走共享 epoll 读循环，
   QUIC 系复用 transport 既有读 goroutine，每 endpoint 省一个
   ReadFrom goroutine。测试：udp_endpoint_receiver_test.go 十一项
   （含真实 direct dialer 端到端）。注意：WAN-hook direct 流量走
   内核快速路径不建 endpoint，推送模式作用于代理出站/DNS 等用户态路径。
   后续两轮生命周期修复已沉淀 git history（`0f485fb8` / `80e381d0`，
   均为 **outbound** 仓库的 commit；该 fork 2026-09 重写历史后这两个 hash
   已作废，以同主题的当前提交为准）

## 相关文档

- `docs/research/` — 生产回归根因分析（video-stutter、UDP P8 collapse、
  TCP sockmap offload、real-kernel-revalidation），最新到 2026-09-10
- `docs/go-1.26-modernization.md` — Go 1.26 工具链与现代化落地记录
- `docs/fork-ci-secrets.md`、`docs/fork-ci-inventory.md` — fork CI 的密钥约束与
  全量清单（含每项运行数、fork 下可行性、建议删除项）
- `docs/fork-contract-validation.md` — fork 三层依赖契约的本地验证流程
- `docs/weak-memory-publication-audit.md`、`docs/remediation-aug25-27.md` —
  弱内存发布审计与 08-25..27 补救计划
- `docs/zh/bbr3-experimental-testing.md` — bbr3 测试与回退
