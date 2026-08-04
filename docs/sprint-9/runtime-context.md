# Sprint 9 Runtime Context

> 2026-08-05：dev + QA 自验时的环境基线。

## 环境

| 项 | 值 |
|---|---|
| OS | Windows + WSL2 Ubuntu |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 |
| Go | 1.26.0 (linux/amd64) |
| 工作树基线 | Sprint 8 HEAD 8e9d1276（control_plane_core.go 1409 行） |
| 拆分后 | control_plane_core.go 625 + 2 新文件（bind/routing） |
| GOEXPERIMENT | heapminimum512kib,randomizedheapbase64 |

## 三通道语义验证命令

```bash
# Channel 1: function set
git show 8e9d1276:control/control_plane_core.go | grep -oE '^func (\(c \*controlPlaneCore\) )?[A-Za-z0-9_]+' | sed 's/^func //;s/(c \*controlPlaneCore) //' | sort -u > /tmp/old.txt
cat control/control_plane_core.go control/control_plane_core_bind.go control/control_plane_core_routing.go | grep -oE '^func (\(c \*controlPlaneCore\) )?[A-Za-z0-9_]+' | sed 's/^func //;s/(c \*controlPlaneCore) //' | sort -u > /tmp/new.txt
diff /tmp/old.txt /tmp/new.txt  # expect: empty (44 = 44)

# Channel 3: numstat (control_plane_core.go must be 0 add / N del)
git diff --numstat control/control_plane_core.go  # expect: 0 784
```

## Sprint 9 关键命令索引

```bash
# Three-channel semantic verification
bash tmp/sprint9-orch-verify.sh

# Full gate (vet/build/test/race) — dev version
bash tmp/sprint9-gate.sh

# End-to-end (ebpf-test + make dae + validate + ebpf-lint)
bash tmp/sprint9-e2e-gate.sh
```

## dev 子代理产出（gitignored）

| 脚本 | 用途 |
|------|------|
| tmp/sprint9-split.py | Python 批量提取（bind + routing 簇，`^func`+`^}` 边界） |
| tmp/sprint9-*.sh | 各阶段验证脚本 |
