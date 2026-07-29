---
sprint: 5
doc: runtime-context
owner: Remy
created: 2026-07-29
source_scripts: [tmp/sprint5-survey.sh, tmp/sprint5-t1-categorize.sh]
---

# Sprint 5 Runtime Context — 技术债清理 + 测量精度升级

> Producer 阶段冻结的运行时基线。Dev 实现前必读；QA 验证以此为前后对照基准。
> 数据源：`tmp/sprint5-survey.sh` + `tmp/sprint5-t1-categorize.sh`（2026-07-29 同 WSL 实例同日，与 Sprint 4 环境一致）。

## T1 — AI 批量测试统计（删除决策依据）

### 当前规模

| 指标 | 值 | 健康区间 |
|------|----|---------|
| test 文件数 | 203 | — |
| src 文件数 | 197 | — |
| test:src 比 | **1.03** | 0.3-0.5（严重超标 2-3 倍） |

### 批量添加测试的 commit 排行（单 commit 新增 *_test.go 数）

| commit | 日期 | 新增数 | 主题 | 处置 |
|--------|------|--------|------|------|
| 85a1fc3c (#970) | 2026-04-22 | **136** | ci/docs/optimize/feature: Enhance control plane | 主删目标 |
| 0486201e | 2026-07-16 | 55 | refactor(architecture): complete semantic refactor foundations | 主删目标 |
| b7fb496d | 2026-07-19 | 15 | refactor(control): complete process-level reload lifecycle | 删目标 |
| ebdbf9a4 | 2023-02-15 | 4 | feat: add sniffing suite (#16) | **原生，绝不碰** |
| d459c838 | 2026-07-14 | 4 | fix(control): strengthen refactor compatibility gates | 评估 |
| 9ef5051f | 2026-07-26 | 3 | fix(control): land pre-merge must-fixes | 评估 |
| 2ca5769b | 2026-07-14 | 3 | feat(routing): add semantic policy foundation | 评估 |
| 其余 | — | ≤2 each | — | 逐个评估 |

### commit #970 (85a1fc3c) 136 文件分类

| 类别 | 数 | 处置 |
|------|----|------|
| helpers (`*_helpers_test`/`*_test_helpers_test`) | 9 | **KEEP**（被引用，删了编译断） |
| bench (`*_bench_test`/`benchmark_test`) | 5 | 删（性能测量非行为契约） |
| fuzz (`*_fuzz_test`) | 5 | **KEEP**（默认保留） |
| 一次性验证 (`*_fix`/`*_bug`/`*_regression`/`*_race`/`*_simulation`/`*_slo`) | 8 | **删（主目标）** |
| integration (`*_integration`/`*_e2e`) | 3 | 评估（依赖真实环境则删） |
| 功能性（其余 `*_test.go`） | 106 | 每模块保留 1-2 核心契约，余删 |

### 全仓库分类清单（删除/保留硬规则）

**KEEP — helpers（9，被引用绝不删）：**
- cmd/run_test_helpers_test.go
- component/outbound/dialer/recovery_test_helpers_test.go
- component/routing/domain_matcher/test_helpers_test.go
- control/bpf_test_helpers_test.go
- control/control_plane_real_domain_test_helpers_test.go
- control/dns_runtime_test_helpers_test.go
- control/kern/tests/bpf_test_helpers_test.go
- control/packet_sniffer_pool_test_helpers_test.go
- control/tcp_copy_test_helpers_test.go

**KEEP — fuzz（6，默认保留）：**
- cmd/runtime_supervisor_fuzz_test.go
- component/sniffing/http_fuzz_test.go
- component/sniffing/internal/quicutils/cipher_fuzz_test.go
- component/sniffing/quic_fuzz_test.go
- component/sniffing/tls_fuzz_test.go
- control/dns_cache_fuzz_test.go

**KEEP — 原生（16，2023 年，绝不碰）：**
- common/bitlist/bitlist_test.go
- common/netutils/ip46_test.go
- component/outbound/dialer_group_test.go
- component/outbound/dialer/socks/socks_test.go
- component/routing/domain_matcher/ahocorasick_slimtrie_test.go
- component/routing/domain_matcher/benchmark_test.go
- component/sniffing/internal/quicutils/cipher_test.go
- component/sniffing/quic_bench_test.go
- component/sniffing/quic_test.go
- component/sniffing/sniffing_bench_test.go
- component/sniffing/tls_test.go
- config/marshal_test.go
- config/outline_test.go
- control/packet_sniffer_pool_test.go
- pkg/config_parser/config_parser_test.go
- pkg/trie/trie_test.go

**KEEP — T3 目标（非批量 commit，Sprint 4 创建）：**
- component/sniffing/benchmark_test.go

**DELETE — 一次性验证（9，主删目标，针对已修 bug 的探索性测试）：**
- control/dns_cache_race_test.go
- control/udp_dispatch_fix_test.go
- control/udp_dispatcher_lifecycle_regression_test.go
- control/udp_hy2_simulation_test.go
- control/udp_quic_initial_regression_test.go
- control/udp_reply_slo_test.go
- control/udp_reuse_simulation_test.go
- control/udp_task_pool_race_fix_test.go
- control/udp_upstream_instability_simulation_test.go

**DELETE — bench（8，性能测量非行为契约，删非基线的）：**
- component/routing/domain_matcher/thp_bench_test.go
- component/sniffing/internal/quicutils/cipher_bench_test.go
- control/dns_cache_bench_test.go
- control/runtime_stats_bench_test.go
- control/tcp_copy_engine_bench_test.go
- control/udp_dispatcher_bench_test.go
- control/udp_proxy_dial_bench_test.go
- control/udp_quic_e2e_bench_test.go
- 注：component/sniffing/sniffing_bench_test.go 是**原生**不删；component/sniffing/benchmark_test.go 是 **T3 目标**不删

**DELETE — 功能性（选择性，每模块保留 1-2 核心契约）：**
- 来源：#970 的 106 + 0486201e 的 50 + b7fb496d 的 15 = 176 functional
- 删除标准：依赖真实网络(net.Listen/Dial)/eBPF 特权；单文件 >400 行；同模块重复覆盖；边缘场景
- 保留标准：纯逻辑/数据契约、解析、路由匹配、缓存、生命周期；确定性快速无外部依赖

### 删除预估

| 项 | 预估 |
|----|------|
| 删除总数 | ~100-120（oneshot 9 + bench 8 + functional 选择性 ~80-100 + integ ~2） |
| 保留总数 | ~80-100（helpers 9 + fuzz 6 + 原生 16 + 核心契约 ~45-65 + T3 目标 1） |
| 目标 test:src 比 | ~0.5（健康区间上沿） |

### helper 依赖链处理（最易踩坑，ai-test-pruning.md）

1. `go vet ./...` 编译驱动，逐个定位 `undefined: xxx`
2. `git grep -n "func xxx" HEAD~1 --` 定位原定义
3. **先排除假阳性**：`git grep -l "func xxx" HEAD~1 -- ':(exclude)*_test.go'` 若命中说明是源码构造函数（非 test helper），无需恢复
4. 真 test helper 恢复到集中的 helper 文件（按包放，注意 build tag 一致）
5. 警惕依赖链深化：恢复 helperA 发现它引用 helperB 的私有类型，需一并恢复

### 删除保护（防误删原生）

删前用 `comm -12 delete_candidates.txt added_by_bulk_commit.txt` 取交集，**只删批量 commit（85a1fc3c/0486201e/b7fb496d）添加的**，2023 原生 16 个绝不碰。

### 验证三件套

`go build ./...` + `go vet ./...` + `go test ./...` 必须全过。

---

## T2 — H7 CPU 基线（sniffHTTPHostHeader 热点）

### H7 CPU profile 证据（来自 Sprint 4，OQ-S4-3）

| 函数 | cum% | 性质 |
|------|------|------|
| sniffHTTPHostHeader | **16.85%** | 纯 CPU 算法热点（每 HTTP 连接嗅探触发） |
| bytes.Index | **9.95%** | sniffHTTPHostHeader 内部循环每行调用 |

### 当前 http.go 实现（75 行，已用 bytes 原语）

```go
func sniffHTTPHostHeader(data []byte) (string, error) {
    for lineStart := 0; lineStart <= len(data); {
        lineEnd := bytes.Index(data[lineStart:], httpLineSep)  // 每行重复 reslice+rescan
        ...
        key, value, found := bytes.Cut(line, httpHeaderSep)     // 每行
        if bytes.EqualFold(bytes.TrimSpace(key), httpHeaderHost) { // 每行
            host := string(bytes.TrimSpace(value))              // 命中时 string() 分配
            ...
        }
    }
}
```

### 优化空间（OQ-S5-1 reformulate 后）

1. **减少 per-line rescan**：循环每行对 `data[lineStart:]` 重复 `bytes.Index`，可考虑单次扫描或直接 case-insensitive 搜索 `\r\nhost:` 模式
2. **跳过 request line**：HTTP 请求行 "GET / HTTP/1.1\r\n" 无 colon → `bytes.Cut` 失败 → continue，是无效工作（首行必非 Host header）
3. **消除 string() 转换分配**：`string(bytes.TrimSpace(value))` @45 + `string(method)` @67 + `common.IsValidHttpMethod(string(method))` @72

### G1/G2 gate

- G1 liveness：`sniffHTTPHostHeader @http.go:21` ← `SniffHttp @http.go:67` ← 生产嗅探（NewStreamSniffer→SniffTcp/SniffHttp）。**LIVE**
- G2 heat：每 HTTP 连接嗅探触发 = **warm**

### verdict 维度（H7）

改后须跑 `-cpuprofile`，pprof `-top -cum` 确认 sniffHTTPHostHeader cum% < 16.85% + bytes.Index cum% < 9.95%。**不可仅用 bench allocs/op 判**（T2 是 CPU 驱动非 alloc 驱动，OQ-S5-1）。

---

## T3 — 当前 bench harness 代码定位（H8 修复目标）

### bytes.NewReader 偏差点（3 处）

component/sniffing/benchmark_test.go（129 行，8 个 bench 函数）：

| 行 | bench 函数 | 当前代码 | 偏差 |
|----|-----------|---------|------|
| 18 | BenchmarkSniffer_SniffTcp_TLS | `NewStreamSniffer(bytes.NewReader(tlsStreamGoogle), 300*time.Millisecond)` | bytes.Reader 无 SetReadDeadline → 强制 async |
| 38 | BenchmarkSniffer_SniffTcp_HTTP | `NewStreamSniffer(bytes.NewReader(payload), 300*time.Millisecond)` | 同上 |
| 125 | BenchmarkSniffer_SniffTcp_NotApplicable | `NewStreamSniffer(bytes.NewReader(payload), 50*time.Millisecond)` | 同上 |

### 生产对照（sniffer.go 读路径选择）

```go
// sniffer.go:156
func (s *Sniffer) readStreamOnce() error {
    if ... {
        if err := s.readStreamOnceWithReadDeadline(); err == nil {  // @160 生产 deadline_sync_read
            ...
    }
    return s.readStreamOnceAsync()  // @166 async fallback（无 deadline 支持时）
}

// sniffer.go:169 生产主路径
func (s *Sniffer) readStreamOnceWithReadDeadline() error {
    if err := s.conn.SetReadDeadline(s.deadline); err != nil {  // @170 生产 TCP
        ...
```

### 偏差机制（L14）

`bytes.NewReader` 实现 `io.Reader` 但不支持 `SetReadDeadline` → sniffer.go:160 `readStreamOnceWithReadDeadline` 调 `s.conn.SetReadDeadline` 失败（或 conn 非 deadline-supporting）→ 回退 `readStreamOnceAsync` @194（spawn goroutine + channel）→ bench 测的是 async 路径分配（13 allocs），而非生产 TCP deadline_sync_read（5 allocs）。

### Sprint 4 基线对照（async vs sync 路径 alloc 差异）

| bench | 路径 | allocs/op |
|-------|------|-----------|
| BenchmarkSniffTcpReadStrategy/legacy_async_read | async（当前 bench 实际走的） | 13 |
| BenchmarkSniffTcpReadStrategy/deadline_sync_read | sync（生产 TCP 实际走的） | 5 |

> 差 8 allocs/op 即是 async 偏差幅度。T3 修复后 SniffTcp_* bench 应趋近 5 而非 13。

### T3 修复策略（OQ-S5-3 选型）

| 方案 | 实现 | 优点 | 风险 |
|------|------|------|------|
| net.Pipe + goroutine 喂数据 + SetReadDeadline | net.Pipe() 两端，一端 goroutine 写 payload，另一端 NewStreamSniffer + SetReadDeadline | 真实 net.Conn，触发 deadline 路径 | goroutine 开销进 bench |
| 自定义 deadlineConn 包装 bytes.Reader 加 SetReadDeadline | struct{r *bytes.Reader}; SetReadDeadline(no-op return nil) | 简单无 goroutine | ⚠️ no-op 不实际限时，但 sniffer.go:160 会尝试成功 → 走 deadline 路径（须 pprof 确认非 async） |

Dev 须用 pprof 确认改后 bench 走的是 deadline_sync_read 路径（非 async），这是 H8 应用成功的决定性证据。

### scope_lock

只改 component/sniffing/benchmark_test.go（harness），**不动 sniffer.go 生产读路径**（H8 是 harness 改进非生产代码改动）。
