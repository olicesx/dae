# dae BPF 代码中 -EPERM 返回路径完整分析

## 1. 唯一的 `return -EPERM` 位置

**文件**: `control/kern/tproxy.c:1477`

```c
// 第 1404-1483 行: route() 函数
static __noinline __s64 route(const __u32 *flag, const void *l4hdr,
                              const __be32 *saddr, const __be32 *daddr,
                              const __be32 *mac)
{
    // ... 初始化 ...
    ctx->result = -ENOEXEC;          // 初始化为 -ENOEXEC (line 1425)
    // ... bpf_loop 遍历所有 routing rule ...
    ret = bpf_loop(active_rules_len, route_loop_cb, &loop_ctx, 0);
    if (unlikely(ret < 0))
        return ret;                  // bpf_loop 出错 (line 1469-1470)
    if (ctx->result >= 0)
        return ctx->result;          // 找到匹配 → 返回路由结果 (line 1471-1472)
    // ... debug print ...
    return -EPERM;                   // ← 唯一的 -EPERM! (line 1477)
}
```

**触发条件**: 遍历完所有 routing rule 后，没有任何一条规则命中（`ctx->result` 保持初始值 `-ENOEXEC`），也没有出现其他错误。

## 2. `route()` 的三个调用点 → 对应的 BPF 程序

### 调用点 A: `do_tproxy_lan_ingress` (第 2248 行)

```
SEC("tc/lan_ingress_l2")  →  tproxy_lan_ingress_l2(skb)  →  do_tproxy_lan_ingress(skb, 14)
SEC("tc/lan_ingress_l3")  →  tproxy_lan_ingress_l3(skb)  →  do_tproxy_lan_ingress(skb, 0)
                                   ↓
                            route() ← line 2248
                                   ↓
     if (s64_ret < 0) { bpf_printk("shot routing: %d", s64_ret); return TC_ACT_SHOT; }
                                   ↓
                            TC_ACT_SHOT → 丢包
```

### 调用点 B: `do_tproxy_wan_egress_tcp` (第 2523 行)

```
SEC("tc/wan_egress_l2")  →  tproxy_wan_egress_l2(skb)  →  do_tproxy_wan_egress(skb, 14)
SEC("tc/wan_egress_l3")  →  tproxy_wan_egress_l3(skb)  →  do_tproxy_wan_egress(skb, 0)
                                   ↓
                            do_tproxy_wan_egress_tcp(skb, ...)  ← line 2479
                                   ↓
                            route() ← line 2523
                                   ↓
     if (s64_ret < 0) { bpf_printk("shot routing: %d", s64_ret); return TC_ACT_SHOT; }
                                   ↓
                            TC_ACT_SHOT → 丢包
```

### 调用点 C: `do_tproxy_wan_egress_udp` (第 2701 行)

```
SEC("tc/wan_egress_l2")  →  tproxy_wan_egress_l2(skb)  →  do_tproxy_wan_egress(skb, 14)
SEC("tc/wan_egress_l3")  →  tproxy_wan_egress_l3(skb)  →  do_tproxy_wan_egress(skb, 0)
                                   ↓
                            do_tproxy_wan_egress_udp(skb, ...)  ← line 2634
                                   ↓
                            route() ← line 2701
                                   ↓
     if (s64_ret < 0) { bpf_printk("shot routing: %d", s64_ret); return TC_ACT_SHOT; }
                                   ↓
                            TC_ACT_SHOT → 丢包
```

## 3. BPF 程序类型分类

| SEC 标签 | 程序类型 | 返回 -EPERM? | 用户空间看到什么？ |
|---|---|---|---|
| `tc/lan_ingress_l2` | TC ingress | ✅ 通过 route() | TC_ACT_SHOT → 超时/丢包 |
| `tc/lan_ingress_l3` | TC ingress | ✅ 通过 route() | TC_ACT_SHOT → 超时/丢包 |
| `tc/lan_egress_l2` | TC egress | ❌ 不调用 route() | N/A |
| `tc/lan_egress_l3` | TC egress | ❌ 不调用 route() | N/A |
| `tc/wan_ingress_l2` | TC ingress | ❌ 不调用 route() | N/A |
| `tc/wan_ingress_l3` | TC ingress | ❌ 不调用 route() | N/A |
| `tc/wan_egress_l2` | TC egress | ✅ 通过 route() | TC_ACT_SHOT → 超时/丢包 |
| `tc/wan_egress_l3` | TC egress | ✅ 通过 route() | TC_ACT_SHOT → 超时/丢包 |
| `tc/dae0peer_ingress` | TC ingress | ❌ 不调用 route() | N/A |
| `tc/dae0_ingress` | TC ingress | ❌ 不调用 route() | N/A |
| `cgroup/sock_create` | cgroup | ❌ 返回 1 (允许) | 正常创建 |
| `cgroup/sock_release` | cgroup | ❌ 返回 1 | 正常释放 |
| `cgroup/connect4` | cgroup | ❌ 返回 1 (允许) | 正常连接 |
| `cgroup/connect6` | cgroup | ❌ 返回 1 (允许) | 正常连接 |
| `cgroup/sendmsg4` | cgroup | ❌ 返回 1 (允许) | 正常发送 |
| `cgroup/sendmsg6` | cgroup | ❌ 返回 1 (允许) | 正常发送 |
| `sockops` | sock_ops | ❌ 返回 BPF_OK | N/A |
| `sk_msg` | sk_msg | ❌ 返回 SK_PASS | N/A |

## 4. -EPERM 与 ifindex 的关系

**结论: -EPERM 与 ifindex/bpf_redirect 完全无关。**

- `route()` 内部的 `return -EPERM` 是纯路由匹配逻辑 —— 当没有任何 routing rule 命中的 fallback
- 涉及 ifindex 的代码路径:
  - `redirect_to_control_plane_ingress()` (line 1504) / `redirect_to_control_plane_egress()` (line 1512): 使用 `PARAM.dae0_ifindex`
  - `tproxy_dae0_ingress` (line 2947): 使用 `redirect_entry->ifindex`（动态值）
  - 这些函数返回的是 `bpf_redirect()` 或 `bpf_redirect_peer()` 的返回值，**不是 -EPERM**

## 5. bpf_redirect() / bpf_redirect_peer() 到无效 ifindex 的行为

| 函数 | 无效 ifindex 时的返回值 | TC 程序中的解释 |
|---|---|---|
| `bpf_redirect(invalid_ifindex, 0)` | **-EINVAL** (内核 net/core/filter.c) | 负值 → TC_ACT_SHOT → 丢包 |
| `bpf_redirect_peer(invalid_ifindex, 0)` | **-EINVAL** | 负值 → TC_ACT_SHOT → 丢包 |
| `bpf_redirect(valid_ifindex, flags)` | TC_ACT_REDIRECT (7) | 成功重定向 |

**关键**: 即使 ifindex 无效，也不会返回 -EPERM。误写 ifindex 只会导致静默丢包（超时），用户看不到 "Operation not permitted"。

## 6. 结论 —— Issue #1024 的 EPERM 来源分析

### 已知事实

1. **dae 的 cgroup/connect4 和 cgroup/connect6 程序始终返回 1（允许）**，从来不返回 -EPERM
2. **dae 的 TC 程序返回 -EPERM 会被内核解释为 TC_ACT_SHOT（丢包）**，用户看到的是超时而非 EPERM
3. **bpf_redirect() 到无效 ifindex 返回 -EINVAL**，不是 -EPERM

### "Operation not permitted" 的可能来源

| 来源 | 可能性 | 说明 |
|---|---|---|
| dae BPF 程序本身 | ❌ 不可能 | 以上分析确认 |
| dae 用户空间 Go 代码 | ⚠️ 可能 | 需检查 control/ 下的 Go 代码错误处理 |
| **BPF 程序加载/附加失败** | **✅ 可能** | cilium/ebpf 加载 BPF 到 cgroup hook 时若权限不足返回 EPERM |
| **seccomp / capabilities** | **✅ 可能** | 缺少 CAP_NET_ADMIN / CAP_BPF |
| **内核配置** | **✅ 可能** | kernel.unprivileged_bpf_disabled=1 |
| **其他 eBPF 程序冲突** | **✅ 可能** | 系统中有其他 cgroup/connect4 程序返回 -EPERM |
| **dae 的 ip rule / iptables 规则** | ⚠️ 可能 | 网络策略导致 connect() 失败 |

### 最可能的原因

如果问题发生在 **启动时**：BPF 程序加载/附加到 cgroup hook 失败（权限不足）。
如果问题发生在 **运行时**：系统中有其他 cgroup BPF 程序拦截了 connect()。
如果问题表现为 **特定流量**：dae 配置的路由规则未覆盖该流量，TC 程序丢包（表现为超时，不是 EPERM）。
