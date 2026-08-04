# Sprint 8 Runtime Context

> 2026-08-05：dev + QA 自验时的环境基线。

## 环境

| 项 | 值 |
|---|---|
| OS | Windows + WSL2 Ubuntu |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 |
| Go | 1.26.0 (linux/amd64) |
| 工作树基线 | Sprint 7 HEAD 0e5a74fc（control_plane.go 4315 行） |
| 拆分后 | control_plane.go 3334 + 4 新文件（parse/dns/datapath/dialtarget） |
| GOEXPERIMENT | heapminimum512kib,randomizedheapbase64 |

## 三通道语义验证命令

```bash
# Channel 1: function set consistency
git show 0e5a74fc:control/control_plane.go | grep -oE '^func (\(c \*ControlPlane\) )?[A-Za-z0-9_]+' | sed 's/^func //;s/(c \*ControlPlane) //' | sort -u > /tmp/old_funcs.txt
cat control/control_plane.go control/control_plane_parse.go control/control_plane_dns.go control/control_plane_datapath.go control/control_plane_dialtarget.go | grep -oE '^func (\(c \*ControlPlane\) )?[A-Za-z0-9_]+' | sed 's/^func //;s/(c \*ControlPlane) //' | sort -u > /tmp/new_funcs.txt
diff /tmp/old_funcs.txt /tmp/new_funcs.txt  # expect: empty

# Channel 3: numstat (control_plane.go must be 0 add / N del)
git diff --numstat control/control_plane.go  # expect: 0 981
```

## Sprint 8 关键命令索引

```bash
# Full gate (vet/build/test/race)
bash tmp/sprint8-gate.sh

# End-to-end (ebpf-test + make dae + validate)
bash tmp/sprint8-e2e-gate.sh

# Semantic verification (three-channel)
bash tmp/sprint8-verify-semantic.sh

# Validate config (with proper permissions — WSL drvfs shows 0777)
cp example.dae /tmp/test-config.dae && chmod 0600 /tmp/test-config.dae
./dae validate -c /tmp/test-config.dae
```

## dev 子代理产出（gitignored）

| 脚本 | 用途 |
|------|------|
| tmp/sprint8-split.py | Python 批量提取（dns/datapath/dialtarget 三簇，按 `^func`+`^}` 边界） |
| tmp/sprint8-fix-imports.py | 修 control_plane.go 提取后的 unused imports |
| tmp/sprint8-*.sh | 各阶段验证脚本 |
