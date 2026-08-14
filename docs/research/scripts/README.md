# 实验脚本（WSL2 性能实验室）

> 这些脚本是本仓库 UDP P8 根因分析实验链的可复现载体（2026-08-15 实测）。
> 执行方式：`wsl -d Ubuntu -e bash <script>`（脚本内自带 netns 重建与清理，幂等）。
> 配套探针二进制在 WSL 侧 `/root/udp_probe/`（socks_proxy/receiver）与 `/root/hp/sender`
> （源码见仓库 `udp_probe/`、`reuseport_test/`）。

## 脚本清单

| 脚本 | 用途 | 关键输出 |
|---|---|---|
| `diag_path.sh` | 路径诊断：dae 是否真的在流量路径上（TC hook / listener / 杀 dae 对照） | 丢包 A/B、ss、tc filter |
| `rcvbuf_test.sh` | rcvbuf 假设筛选（Step 1：全局 sysctl 8MiB vs 默认） | P8 丢包率对比 |
| `rcvbuf_step2.sh` | 归因（Step 2：仅代码 SetReadBuffer，sysctl 默认） | 确认 dae ingress rcvbuf 是否瓶颈 |
| `socks_ab.sh` | socks 路径（真实 honk 场景）A/B：BASE vs FIX | receiver 报告（per-flow loss/reorder）+ dae CPU |
| `socks_attr.sh` | 归因场景 A（无 dae 直收）与 C（全局 rmem 8MiB） | 丢包段定位 |
| `socks_seg.sh` | 三段分解：dae→proxy 段（proxy `-count-only`）+ pprof | dae 处理率、pprof 热点 |
| `alloc_profile.sh` | 分配画像（饱和负载 heap profile） | alloc_space/alloc_objects top |

## 结论速查（实验链结果，详见 `udp-p8-collapse-root-cause.md`）

1. `diag_path.sh` 证明：fallback direct 配置下流量**不经 dae 用户态**（NAT 直通）——ab_bench T2 测的是 NAT 路径
2. `rcvbuf_test/step2.sh`：8MiB 的 31%→0.1% 改善属于 iperf3 server rcvbuf（NAT 终点），dae 侧 SetReadBuffer 无实测收益（已 revert）
3. `socks_seg.sh`：socks 路径 96% 丢包全在 dae 用户态内部；pprof 定位 Syscall6 40.9%（写 syscall 31%）
4. `alloc_profile.sh`：改造后总分配 -62%/-60%（owned task）、WriteBatch -94%（scratch 池化）

## 注意事项

- 脚本内路径（`/root/daes_bench/...`、`/root/udp_probe/...`）为 WSL 侧布局，真实内核复测前按
  `real-kernel-revalidation.md` 调整
- sender 饱和速率在 WSL2 漂移大（8.5-17 Gbps）——A/B 必须交替多轮，单次对比不可信
- 全部脚本已幂等（pkill/清理先行），可重复执行
