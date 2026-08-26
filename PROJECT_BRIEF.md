# kdae 分支说明（重构线）

> kdae 是 dae 的架构重构/性能优化分支。本文是这条线的精简总索引，
> 取代原 706 行的 sprint 逐轮记录（sprint-1..9 过程文档已随做减法移除，
> 结论沉淀在本文与 git history 中）。

## 分支概况

- 基线：daeuniverse/dae（main），Go 1.26 + eBPF C（cilium/ebpf v0.20）
- 主线：语义等价重构 → 生命周期/分配优化 → 架构拆分 → 做减法（当前阶段）
- 行为变更记录见 `CHANGELOGS.md` 的 Unreleased 段（sniffing_timeout、
  bootstrap_resolver 默认值、so_mark_from_dae 语义、disable_thp、路由合并语义等）

## 重构成果（结构性）

- `control/control_plane.go` 4315 → ~3200 行，拆出 parse / dns / datapath /
  dialtarget 4 个子系统文件（Sprint 8）
- `control/control_plane_core.go` 1409 → 625 行，拆出 bind / routing（Sprint 9）
- `cmd/run.go` 拆出 run_config / run_controlplane / run_reload / run_serve /
  runtime_supervisor / reload_manager
- DNS 控制器拆为 dns_controller_{bpf,cache,forwarder,handle,response,runtime}
- 拆分方法论：三通道语义验证（函数集合一致 / body diff 仅机械副产品 /
  numstat 纯删除），配合 `make ebpf-test` 与 race 测试

## 依赖（fork pin）

- `github.com/olicesx/quic-go`、`github.com/olicesx/outbound`（go.mod replace）
- fork 改动：GSO 切包、datagram 超时契约、hy2 缓冲/关闭、PacketBatchWriter
- fork 侧验证：`scripts/fork-cross-repo-test.sh`（解析 replace pin，跑 fork 自身测试）

## 验证 gate

```bash
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
   后续两轮生命周期修复已沉淀 git history（0f485fb8/80e381d0）：
   sender/回调栈不得同步 Close（自死锁 + closeOnce 占死）、mark-only
   退场由独立 goroutine 兜底关 conn、注册同步投递与队列关闭的竞态

## 相关文档

- `docs/research/` — 生产回归根因分析（video-stutter、reload EBUSY、
  UDP P8 collapse、TCP sockmap offload），最新到 2026-08-16
- `docs/en/semantic-architecture-refactor-plan.md` — 重构总计划
