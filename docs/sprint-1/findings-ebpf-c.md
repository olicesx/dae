# T7 — control/kern/ eBPF C 程序审阅发现清单

> 只读审阅，未修改任何源码。
> 审阅对象：`control/kern/tproxy.c`（~3170 行）、`ebpf_sync_defs.h`、`headers/`（28 个头文件）、`tests/`（bpf_test.c/h）
> 对照 Go 侧：`control/bpf_bpfel.go`、`common/consts/ebpf.go`、`common/consts/ebpf_sync_spec.json`
> 日期：2026-07-03

## 发现汇总

| 严重度 | 数量 |
|---|---|
| P0 | 0 |
| P1 | 0 |
| P2 | 4 |
| P3 | 5 |

**总体评价**：代码质量优秀。边界检查、verifier 友好性、kernel 兼容性版本门槛、Go↔C 结构同步均到位。主要问题集中在风格一致性和理论竞态（影响有限）。

---

## 发现清单

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P2 | [tproxy.c:1810-1815](control/kern/tproxy.c#L1810-L1815), [tproxy.c:1673-1680](control/kern/tproxy.c#L1673-L1680) | `__mark_tcp_seen`/`__mark_udp_seen` 的"先 `bpf_map_delete_elem` 再 `bpf_map_lookup_elem`"路径在多 CPU 上存在 TOCTOU 竞态。若两个 CPU 同时处理同一 4-tuple 的纯 SYN（罕见但理论可能），一个 CPU 删除后另一 CPU 的 lookup 返回 NULL 导致重复创建/覆盖路由元数据。BPF HASH map 无事务保证。 | 影响有限（conntrack 是 best-effort，janitor 会兜底）。如需严谨可用 `BPF_MAP_UPDATE_ELEM` 的 `BPF_NOEXIST` 配合重试，或为 SYN 路径单独走 update-only 而非 delete+lookup。 |
| P2 | [tproxy.c:2383-2386](control/kern/tproxy.c#L2383-L2386) | `pid_is_control_plane` 的回退路径 `if ((skb->mark & 0x100) == 0x100) return true;` 使用硬编码 magic number `0x100`，未与 Go 侧常量（如 `consts.SoMark` 或类似）同步。一旦 Go 侧修改 mark 位含义，C 侧不会跟随。 | 提取为 `ebpf_sync_defs.h` 中的宏（如 `#define CONTROL_PLANE_MARK_BIT 0x100`），并由 `ebpf_sync_spec.json` 同步到 Go 侧。 |
| P2 | [tproxy.c:1455-1460](control/kern/tproxy.c#L1455-L1460) | `route()` 从 `routing_meta_map` 读取 `active_rules_len` 时仅检查 `*active_rules_len_ptr <= MAX_MATCH_SET_LEN`，无下限保护。若 userspace 写入 0 或异常小值（如初始化前未设置），`bpf_loop(0, ...)` 不执行回调直接返回，所有流量走 `-EPERM` 被丢弃（TC_ACT_SHOT）。 | 增加 `active_rules_len >= 1` 的最小值断言，或当 len==0 时显式放行（return TC_ACT_OK 而非 SHOT）。当前行为是"无规则即拒绝"，是否符合产品语义需确认。 |
| P2 | [tproxy.c:295-301](control/kern/tproxy.c#L295-L301) | `cookie_pid_map` 为普通 HASH（虽带 `BPF_F_NO_PREALLOC`），依赖 `cgroup/sock_release` hook 清理。若进程被 `SIGKILL` 或 cgroup 移除时 hook 未触发（极端情况），entry 会残留至 `MAX_COOKIE_PID_PNAME_MAPPING_NUM`（65536）上限。 | 影响低（65536 上限足够大，且 sock_release 通常可靠）。可考虑增加 userspace janitor 周期性扫描 `last_seen_ns` 兜底清理，与 conn_state_map 一致。 |
| P3 | [tproxy.c:2445-2452](control/kern/tproxy.c#L2445-L2452) | `wan_outbound_is_alive` 函数开头已 `if (dport == bpf_htons(53)) return true;` 提前返回，但下面 `l4proto == IPPROTO_UDP` 分支内仍有 `if (dport == bpf_htons(53)) domain_idx = 1;`，此为死代码（dport==53 已在上层返回）。 | 删除 UDP 分支内的冗余 `if (dport == bpf_htons(53))` 判断，直接 `domain_idx = 1`。 |
| P3 | [tproxy.c:2725-2735](control/kern/tproxy.c#L2725-L2735) | `do_tproxy_wan_egress_udp` 中 `fast_path_skip_routing:` 标签后的语句块缩进比函数体多一个 tab（clang-format 不一致）。虽然 `make ebpf-lint` 显式忽略 `LEADING_SPACE/SPACING`，但视觉上易误读为嵌套块。 | 修正缩进与函数体对齐；或若 clang-format 配置允许则统一风格。 |
| P3 | [tproxy.c:1764](control/kern/tproxy.c#L1764), [tproxy.c:1898](control/kern/tproxy.c#L1898) | `__mark_udp_seen`/`__mark_tcp_seen` 对 `bpf_stats_map`（PERCPU_ARRAY）使用 `__sync_fetch_and_add`。PERCPU_ARRAY 每个 CPU 独立计数，本无需原子操作；使用原子指令虽无害但冗余，且部分旧 clang 版本会生成更重的指令。 | 改为 `(*overflow_count)++` 即可；保留原子操作也无功能影响。 |
| P3 | [Makefile:121](Makefile#L121) | `ebpf-lint` 通过 `--ignore` 显式忽略 `CAMELCASE,VOLATILE,SPACING,LEADING_SPACE,OPEN_ENDED_LINE,BLOCK_COMMENT_STYLE` 等 checkpatch 类型，说明 tproxy.c 存在这些风格问题但已被项目接受。例如：标识符命名混用风格——`routing_meta`、`build_routing_meta`、`has_routing`、`publish_routing_meta` 是 Go/camelCase 风格，而 `last_seen_ns`、`is_wan_ingress_direction`、`parse_transport_fast` 是 C/snake_case 风格。 | 风格统一非阻塞，但若团队规范明确（AGENTS.md 未强制 BPF 命名风格），可逐步收敛。`volatile` 用于发布语义（[tproxy.c:336](control/kern/tproxy.c#L336)）是合理的，忽略 VOLATIME 警告正确。 |
| P3 | [tests/bpf_test.c:80](control/kern/tests/bpf_test.c#L80) | 注释 `// Scheme3: Store routing result in conn_state_map...` 是历史命名遗留（"Scheme3" 暗示曾存在中文 "方案3"）。虽已是英文，但上下文缺失，新读者无法理解 "Scheme3" 指什么。 | 改为描述性注释，如 `// Store routing result in conn_state_map (replaces former routing_tuples_map)`。 |

---

## 已检查无问题的检查点

### D3 Go↔C 结构同步 ✓

- `ebpf_sync_defs.h` 中 `OUTBOUND_*`（0x0/0x1/0xFC/0xFD/0xFE/0xFF/0xFE）、`MatchType`（0-13）、`L4ProtoType`（1/2/3）、`IpVersionType`（1/2/3）与 `ebpf_sync_spec.json` **完全一致**。
- `bpf_bpfel.go` 由 bpf2go 自动生成，结构布局（含编译器自动 padding）与 C 侧匹配。抽检：
  - `bpfConnState`：C 的 `__u64 last_seen_ns` 触发 8 字节对齐，前置 6 字节隐式 padding → Go 显式 `_ [6]byte` 匹配 ✓
  - `bpfDaeParam`：`dae0peer_mac[6]` + `padding_after_mac[2]` + 后续 u8/u16/u32 布局逐字节匹配 ✓
  - `bpfRoutingHandoffEntry`：内层 `routing_result` 33 字节补齐到 36（4 字节对齐），外层补齐到 48（8 字节对齐）→ Go `_ [3]byte` + `_ [4]byte` 匹配 ✓
  - `bpfMatchSet`：C 的 `enum __attribute__((packed)) MatchType` 占 1 字节 → Go `Type uint8` 匹配 ✓
  - `bpfTuplesKey`：C 末尾 `__u8 l4proto` 后补 3 字节 padding 到 4 字节对齐 → Go `_ [3]byte` 匹配 ✓
- 字节序：网络序字段（`__be16`/`__be32`）在 C 用 `bpf_htons`/`bpf_ntohs`，Go 侧通过 `structs.HostLayout` 处理，一致 ✓
- `MAX_MATCH_SET_LEN`（32*32=1024）在 C 宏与 Go `consts.MaxMatchSetLen` 一致 ✓

### D5 代码质量 ✓

**边界检查** ✓
- 所有 `bpf_map_lookup_elem` 返回值均检查 NULL。
- Packet 解析严格遵循 `(void *)(ptr + 1) > data_end` 模式（[tproxy.c:580-620](control/kern/tproxy.c#L580-L620) 等多处）。
- IPv4 `ihl < 5` 拦截畸形头（[tproxy.c:625](control/kern/tproxy.c#L625)）。
- IPv6 扩展头循环上限 `IPV6_MAX_EXTENSIONS=8`（[tproxy.c:692](control/kern/tproxy.c#L692)），防止无限循环。
- 分片包非首片返回 `PARSE_FRAGMENT` 走特殊路径（[tproxy.c:640](control/kern/tproxy.c#L640), [tproxy.c:703](control/kern/tproxy.c#L703)）。
- `route_match_domain_set` 检查 `bitmap_word_idx >= MAX_MATCH_SET_LEN / 32`（[tproxy.c:1125](control/kern/tproxy.c#L1125)）。

**bpf_probe_read / 直接解引用** ✓
- 未使用危险的裸指针解引用读取内核数据。
- `task_struct` 读取用 `BPF_CORE_READ(task, mm, arg_start)`（CO-RE，[tproxy.c:3053](control/kern/tproxy.c#L3053)）。
- 用户态字符串用 `bpf_core_read_user_str`（[tproxy.c:3057](control/kern/tproxy.c#L3057)），有 `< 0` 错误检查。

**尾调用 / verifier 限制** ✓
- 主路径用 `bpf_loop`（5.17+，有运行时版本门槛 `consts.BpfLoopFeatureVersion`，[control_plane.go:410](control/control_plane.go#L410)）而非 `bpf_tail_call` 循环。
- `bpf_tail_call` 仅在 tests/ 的 entry_call_map 中使用（max_entries=1）。
- `route()` 标记 `__noinline` 控制栈深度；`route_loop_cb` 同样 `__noinline`。
- 大结构（`parse_transport_ctx` ~128B、`parsed_packet`、`route_ctx`、`conntrack_args`）通过 PERCPU_ARRAY scratch map 分配，规避 512 字节栈限制 ✓

**kernel 兼容性** ✓
- `bpf_loop`（5.17）、`bpf_sk_assign`（5.7）、`bpf_redirect_peer`（6.8，运行时回退到 `bpf_redirect`）、`bpf_skb_change_head`（5.8）、`bpf_sk_lookup_udp`/`bpf_skc_lookup_tcp`（5.9）、`bpf_get_socket_cookie`（5.7）等所有特性在 `consts` 中有 `FeatureVersion` 常量，且 `control_plane.go` 启动时检查内核版本。
- `BPF_NO_PRESERVE_ACCESS_INDEX` 显式禁用 CO-RE 隐式重定位（[tproxy.c:6](control/kern/tproxy.c#L6)），规避 GCC 15 DTE 问题。

**注释语言** ✓
- `grep [\x{4e00}-\x{9fff}]` 扫描整个 `control/kern/`（含 headers/、tests/）**无任何 CJK 字符**。符合 AGENTS.md 强制要求。

**license** ✓
- `SEC("license") const char __license[] = "Dual BSD/GPL";` 正确（[tproxy.c:3167](control/kern/tproxy.c#L3167)）。

**Map flags** ✓
- 所有 HASH map（`cookie_pid_map`、`conn_state_map`、`routing_handoff_map`、`domain_routing_map`、`redirect_track`）使用 `BPF_F_NO_PREALLOC`，避免大表预分配内存膨胀。
- `conn_state_map` 带 `LIBBPF_PIN_BY_NAME` 支持冷启动复用。
- PERCPU_ARRAY 用于 scratch（`parse_ctx_scratch_map`、`pkt_scratch_map`、`route_ctx_scratch_map`、`conntrack_args_map`、`wan_egress_route_scratch_map`）和统计（`bpf_stats_map`），避免锁竞争。

**测试覆盖** ✓
- `tests/bpf_test.c` 覆盖 dport/source_port/ipset/source_ipset/l4proto/ipversion/fallback 等路由匹配场景的 match/mismatch 对（pktgen/setup/check 三段式）。
- `bpf_test.go` + `bpf_test_helpers_test.go` 提供用户态驱动。
- `setup_cached_routing_result` 验证 conn_state 缓存路径（[bpf_test.c:55-79](control/kern/tests/bpf_test.c#L55-L79)）。

---

## 简报

- **发现总数**：9（P0=0, P1=0, P2=4, P3=5）
- **最突出问题**：理论 TOCTOU 竞态（P2，conntrack 删除+lookup 非原子，影响有限）；`pid_is_control_plane` 硬编码 mark 位 `0x100` 未同步 Go 侧常量（P2）。
- **亮点**：Go↔C 结构同步由 bpf2go + ebpf_sync_spec.json 双向保证，边界检查与 verifier 友好性（PERCPU scratch map、bpf_loop 替代 tail_call 循环）成熟，全英文注释合规。
- **产出文件**：[docs/sprint-1/findings-ebpf-c.md](docs/sprint-1/findings-ebpf-c.md)
