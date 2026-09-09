# 实验性拥塞控制 bbr3：测试与回退

本页面向参与测试的人。**先读「证据等级」再决定要不要测。**

控制器实现与完整测试/反馈指南在 outbound 仓库：
[`docs/bbr3-experimental.md`](https://github.com/olicesx/outbound/blob/feat/bbr3-experimental/docs/bbr3-experimental.md)
（本页只讲 dae 侧怎么开、怎么退、怎么报）。

## 1. 证据等级

| 项 | 现状 |
|---|---|
| 证据来源 | **仅用户态仿真**（单流、无竞争、40ms FIFO、n=5） |
| 延迟 | 两个测试场景 p95 比原版 BBR 低 39%/44%（102 vs 168ms；185 vs 333ms） |
| 吞吐 | 高 0.6%/1.2%（18.92 vs 18.80；17.63 vs 17.42 Mbps）；在 accurate 场景**输给** sing-quic 适配版（18.92 vs 19.18） |
| 未覆盖 | 真实公网、竞争流/公平性、多连接、长时间运行、ECN |
| 实现性质 | 自制实现，**未验证 BBRv3 一致性，不是参考实现** |
| hint 门控 | 经诊断证明惰性（13/13 run 零 lift），**默认关闭，不建议开启** |

结论：**默认关闭、不部署为默认值**。测试目的是收集真实网络下的对照数据，不是宣称性能提升。

## 2. 构建

```bash
git checkout feat/bbr3-experimental
make dae
```

该分支把 `go.mod` 的 outbound 钉到 fork 的 `feat/bbr3-experimental`
（`v0.0.0-sticky-ip.0.20260909101419-8ef1d1b9d0a6`）。若你的环境走代理拉不到该提交：

```bash
GOPROXY=direct GOPRIVATE='github.com/olicesx/*' go mod download github.com/olicesx/outbound
```

## 3. 启用

在 dae 配置的 `node` 段里给 TUIC 链接追加 `cc_override=bbr3`：

```text
node {
    t1: 'tuic://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3&cwnd=2500000'
}
```

| 参数 | 说明 |
|---|---|
| `cc_override` | 只在客户端本地生效，**不发给服务端**，服务端无需支持 |
| `congestion_control` | 仍按原逻辑发给服务端并回显；服务端写 `bbr`/`cubic`/留空都可以 |
| `cwnd` | 对 bbr3 是接入带宽上限（字节/秒），只作上限不是目标；`0`/不设 = 纯探测（**不在证据覆盖范围内**） |
| 白名单 | `bbr`、`cubic`、`new_reno`、`brutal`、`bbr3`；非法值在首次拨号时报错 |

复现仿真条件用 `cwnd=2500000`（= 20 Mbps）。

### 3.1 确认真的生效

`dae validate` **不解析节点链接**（非法端口也会放行），别用它验证。把日志调到 debug：

```text
global {
    log_level: debug
}
```

每条 TUIC 连接安装控制器时输出：

```text
level=debug msg="installing experimental bbr3 congestion controller" cc=bbr3 hint_bps=2500000
```

看不到这行 = 没生效（链接写错、拼写错误、或走了其他节点）。`cc_override` 拼错时表现为**该节点连接失败**，不会在配置校验阶段报错。

## 4. 回退（三级，任选）

**① 链接级（立即生效，无需重编译，首选）**

```text
# 去掉 cc_override，回到服务端回显
tuic://...?congestion_control=bbr

# 或本地强制原版 BBR
tuic://...?congestion_control=bbr&cc_override=bbr
```

**② 代码级**

```bash
git checkout kdae            # 切回基线分支
# 或保留分支反向提交：git revert <本分支提交>
```

**③ 产品级**：把 `go.mod` 的 outbound 钉回旧提交

```bash
go mod edit -require github.com/daeuniverse/outbound@v0.0.0-sticky-ip.0.20260907140516-07427f11deb3
go mod edit -replace github.com/daeuniverse/outbound=github.com/olicesx/outbound@v0.0.0-sticky-ip.0.20260907140516-07427f11deb3
go mod tidy
```

不设置 `cc_override` 时，行为与接入前**完全一致**。

## 5. 测试要报什么

请对照测量并附上：

- 环境：dae 提交、outbound 提交、服务端软件与版本、内核版本、地区/运营商
- 场景：下载/上传/视频/游戏/多连接并发，各测多久
- 对照臂：同一节点同一时间，`bbr` 与 `cc_override=bbr3`（建议同 cwnd）
- 指标：goodput、p95/p99 延迟、队列丢包、CPU 占用、连接异常/重连次数
- 是否出现 bbr3 明显劣于 bbr 的场景（这是最有价值的信息）

反馈模板见
[`docs/bbr3-experimental.md` §6](https://github.com/olicesx/outbound/blob/feat/bbr3-experimental/docs/bbr3-experimental.md)，
或直接提 issue（模板 `[bbr3]`）。
