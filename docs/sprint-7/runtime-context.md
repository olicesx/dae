# Sprint 7 Runtime Context

> 2026-08-05：dev + QA 自验时的环境基线。

## 环境

| 项 | 值 |
|---|---|
| OS | Windows + WSL2 Ubuntu |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 |
| Go | 1.26.0 (linux/amd64) |
| clang | 18.1.3 |
| 工作树 | clean (HEAD ca61b195) |
| branch | kdee（基于 kdee 创建） |
| GOEXPERIMENT | heapminimum512kib,randomizedheapbase64（Makefile 默认） |

## fork 仓库基线

| 仓库 | HEAD | dae replace 对齐 |
|------|------|------------------|
| outbound | c5b8ecc (origin/perf/complete-optimizations) | ✅ 匹配 dae replace sticky-ip.0.20260803032050-c5b8ecc17ecc |
| quic-go | dff8aaa5 (origin/perf/datagram-pool) | ✅ 匹配 dae replace 20260803000957-dff8aaa58e14 |

## 网络

| 资源 | 状态 | 备注 |
|------|------|------|
| github.com 直连 | 不稳（TLS reset/timeout） | Sprint 6 L18a 已用 gh-proxy 镜像（git config insteadOf） |
| golang.org 直连 | 超时（i/o timeout） | Sprint 7 L21：T2 默认 `GOPROXY=https://goproxy.cn,direct` |
| goproxy.cn | 可用 | fork deps 下载正常 |

## Sprint 7 关键命令索引

```bash
# T1 smoke（红绿）
bash scripts/deletion-protection-scan.sh control/bpf_bug_verification_test.go   # 期望 exit 1 + 4 hits
bash scripts/deletion-protection-scan.sh control/__nonexistent__.go             # 期望 exit 0

# T2 dry-run（解析）
bash scripts/fork-cross-repo-test.sh --dry-run

# T2 全量 advisory（~12 分钟）
bash scripts/fork-cross-repo-test.sh --short

# T2 严格模式（fork bump 决策时用）
bash scripts/fork-cross-repo-test.sh --short --strict

# Sprint gate
bash tmp/sprint7-gate.sh
```
