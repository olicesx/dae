# Sprint 1 发现清单 — T12（config/）

> 只读审阅，未修改任何源码。审阅对象见 `plan.md` 的 T12 章节。
> 行号基于审阅时的工作区状态，可能随后续提交漂移。

严重度图例：P0 致命 / P1 严重 / P2 一般 / P3 建议。

审阅文件：`config/config.go`、`parser.go`、`decode.go`、`marshal.go`、`outline.go`、`desc.go`、`patch.go`、`config_merger.go`、`bootstrap_resolver.go`（+ `function_union_test.go`、`so_mark_test.go`、`decode_test.go`、`outline_test.go`、`bootstrap_resolver_test.go`、`marshal_test.go` 用作覆盖度参照）。

---

## 发现清单

| 严重度 | 文件:行号 | 问题描述 | 改进建议 |
|---|---|---|---|
| P2 | config/config_merger.go:113-140 (`unsqueezeEntries`) | **include 路径匹配为空时静默忽略**：`filepath.Glob` 对无匹配的 pattern（含字面文件名拼错，如 `include: partols.dae`）返回 `nil, nil`（无错误）。随后 `len(unsqueezed)==0` 被显式置为 nil，调用方 `dfsMerge` 遍历空 childEntries 直接跳过。结果是：拼错的 include 文件**不报错**，整个被包含文件的配置（节点/路由/DNS）静默丢失，运行时表现为节点缺失或路由失效，排障困难。当前实现无法区分"刻意可选的 glob"与"字面拼错"。 | 对字面路径（不含 glob 元字符 `*?[`）单独用 `os.Stat` 检测：存在则加入、不存在则返回明确错误（如 `include file not found: %v`）；仅对含 glob 元字符的 pattern 保留"匹配为空即跳过"的可选语义。或至少在匹配为空时通过 logger 发出 warning。 |
| P2 | config/bootstrap_resolver.go:17-34 (`BootstrapResolvers`) | **显式配置强制单点解析器，丢失默认的双机冗余**：默认值提供两个解析器（`119.29.29.29:53`、`223.5.5.5:53`）用于容错；但用户一旦设置 `global.bootstrap_resolver`，`desc.go` 明确说明"uses only the configured resolver"，函数仅返回单元素切片。bootstrap 解析发生在 dae DNS 路由就绪前（解析 DNS upstream 主机名、dial_mode real-domain 探测），若该单点解析器不可达或被污染，整个引导链路无 fallback。`desc.go` 文档将此描述为"disables those defaults"即刻意设计，但缺乏可靠性权衡说明。 | 允许 `bootstrap_resolver` 接受逗号分隔的多个解析器（与 `udp_check_dns` 等其他全局字段一致），保留显式覆盖语义的同时恢复冗余；或在文档/启动日志中明确提示"已从双机降为单机引导解析"。 |
| P2 | config/config_merger.go:188-193 (`mergeItems`) + dfsMerge:177-185 | **include 合并语义隐式且未文档化**：`mergeItems` 将 father 与 child 的 items **直接拼接**（father 在前、child 在后），不做任何冲突检测。对 `parser.go` 的 `ParamParser` 而言：标量字段（如 `log_level`）表现为"后者覆盖前者"（child 覆盖 father），切片字段（如 `tcp_check_url`、`subscription`）表现为"两者累积"。这一"标量覆盖、切片累积"的混合语义未在任何注释或文档中说明，用户难以预测多文件合并结果，且无冲突告警。`config.go:New` 注释仅提及"merging and deduplication for section names has been executed"，但实际无键级冲突处理。 | 在 `config_merger.go` 顶部补充合并语义文档（标量 last-wins、切片累积、child 覆盖 father 的顺序）；或在检测到同一标量键在多文件重复设置时发出 warning，帮助用户发现意外的覆盖。 |
| P3 | config/patch.go:28-35 (`patchTcpCheckHttpMethod`) | **patch 通过 logrus 静默改写而非返回错误**：该 patch 对非法 HTTP method 仅 `logrus.Warnf` 并回退为 `CONNECT`，不返回 error。与同文件其他 patch（`patchBootstrapResolver` 非法值即报错、`patchMustOutbound` 类型错误即报错）契约不一致。`patches` 列表的设计预期是返回 error 中断解析，此处改为"静默修正"，可能让用户在日志噪声中错过配置错误。该 patch 幂等（`CONNECT` 在 `IsValidHttpMethod` 合法集合内，二次调用 no-op），无功能缺陷。 | 统一 patch 契约：要么所有 patch 对非法输入返回 error，要么明确文档化哪些 patch 会"宽容修正"。此处建议保持当前宽容行为但将日志级别提升或在错误信息中带原值与配置位置。 |
| P3 | config/parser.go:155-166 (`ParamParser` 切片分支) | **空值切片字段产生 `[""]` 而非空切片**：当用户写 `tcp_check_url:`（值为空）时，`strings.Split("", ",")` 返回 `[""]`（长度 1），`len(values)>0 && !field.Set` 为真（清空默认值），随后对空串调用 `common.FuzzyDecode` 成功（string 类型直接 SetString），最终得到含一个空串的切片而非空切片。该空串后续作为 check URL 使用会导致连接失败。是否可触发取决于上游 `config_parser` 词法是否允许空值参数。 | 在切片解码前显式判断：若 `itemVal.Val == ""` 且字段为 string 元素切片，按空切片处理（保留默认值或置空），并在非预期位置给出 warning。 |
| P3 | config/marshal.go:17 (`Marshal` 注释) | **文档化的注入防护缺失**：文件首部注释 `Marshal assume all tokens should be legal, and does not prevent injection attacks.` 明确声明不防注入。`marshalLeaf` 对字符串值使用 `strconv.Quote`（可正确转义引号），但对 `*config_parser.Function` 等结构化值直接调用其 `String()` 方法无转义。若 Marshal 产物被回写后重新解析，恶意构造的 function/param 字符串可注入额外配置项。当前 Marshal 主要用于 outline 导出与调试，非配置回写闭环，实际风险低。 | 若 Marshal 存在"回写再解析"用途，需对 function/param 的字面值做转义或校验；若仅用于只读导出，在注释中明确"禁止用于生成可执行配置"的使用约束即可。 |
| P3 | config/outline.go:49-55 (`ExportOutlineJson`) | **库函数 panic 兜底**：`jsoniter.MarshalIndent` 失败时直接 `panic(err)`。对已知 `*Outline` 结构（全为基础类型切片），序列化失败几乎不可能，但 panic 出现在被导出的库函数中违反"返回 error"惯例。`ExportOutline`（非 JSON 版）本身不 panic，仅 JSON 封装层 panic，调用方无法优雅处理。 | 改为 `ExportOutlineJson(version string) (string, error)`，由调用方决定错误处理；或在注释中明确 panic 仅限"内部契约违反"场景。 |

---

## 检查点覆盖说明（已检查、未发现问题）

- **D5 parser 对畸形输入容错**：已检查，整体健壮。`parser.go` 的 `ParamParser` 对未知 key 返回 `unexpected key` 错误、类型不匹配返回 `cannot be convert to %v`、无 key 的裸文本返回 `unsupported text without a key`、不支持的数据类型走 `ignoreTypeSet` 白名单或报错。`New` 对未知 section 返回 `unknown section`、缺失 required section 返回 `section %v is required but not provided`。错误信息均包含具体 key/section 名与值，可定位。
- **D5 decode 类型转换边界**：已检查，无溢出风险。`common.FuzzyDecode`（`common/utils.go:103`）按目标类型位宽调用 `strconv.ParseUint(val, 0, bits)`：uint16（`TproxyPort`/`PprofPort`）用 16 位、uint32（`SoMarkFromDae`/`BpfConnStateMapSize`）用 32 位，越界值直接返回 false 触发解析错误。`time.Duration` 走 Int64 分支的 `time.ParseDuration`，语义正确。bool 接受 `true/t/1/y/yes/on` 与 `false/f/0/n/no/off`，覆盖面合理。
- **D5 function_parser 健壮性**：已检查，良好。`ParseFunctionOrString`/`ParseFunctionListOrString`（`config.go:50-100`）对 string、`*Function`、`[]*Function`、其他类型穷举分支，非法类型返回带 `%T` 的明确错误；仅 `FunctionOrStringToFunction` 等 legacy 包装器按设计 panic（已加注释说明保留历史 API）。`function_union_test.go` 覆盖 string/function/single-slice/invalid-length/unsupported-type 全分支。
- **D6 config_merger 循环 include 检测**：已检查，正确。`readEntry` 在处理前将 entry 写入 `entryToSectionMap` 标记已访问，DFS 中遇到已存在 entry 即返回 `ErrCircularInclude`，错误信息以 `father -> entry -> ... -> father` 形式提示环。`EnsureFileInSubDir` 阻断 `..` 路径穿越，文件权限检查 `fi.Mode()&0037 > 0` 拒绝组可写/其他可访问的过宽权限。
- **D6 patch 幂等性**：已检查，全部幂等。`patchMustOutbound` 首次剥离 `must_` 前缀并追加 `must` param，二次调用前缀已无、不重复追加；`patchTcpCheckHttpMethod` 首次回退为 `CONNECT`（在 `IsValidHttpMethod` 合法集合内），二次调用 no-op；`patchEmptyDns` 仅在 `Fallback == nil` 时填充默认，二次调用已非 nil 跳过；`patchBootstrapResolver` 纯校验无副作用。
- **D6 bootstrap resolver 可靠性（格式校验部分）**：已检查，格式校验可靠。`BootstrapResolvers` 用 `netip.ParseAddrPort` 严格校验（拒绝无端口、非 IP 等格式），并通过 `patchBootstrapResolver` 在 `New` 阶段早期失败，`bootstrap_resolver_test.go` 覆盖默认/显式覆盖/非法值三场景。可靠性隐患见上方 P2 条目（单点冗余丢失）。
- **D6 配置校验完整性**：已检查，核心校验齐备。required section（`global`/`routing`）强制、required field（`Group.policy`、各 `Fallback`）强制、unknown section/key 拒绝。`so_mark_test.go` 验证 `so_mark_from_dae: 0` 显式设置与缺失两种场景的 `SoMarkFromDaeSet` 标记正确性。
- **section 顺序非确定性（已排除）**：`convertMapToSections`（`config_merger.go:163`）遍历 map 产生无序 sections，但 `New`（`config.go:127-145`）通过遍历固定顺序的 `configSectionSpecs` 进行解码、用 `nameToSection` map 做查找，section 级顺序不影响解析结果；section 内 items 顺序由 `mergeItems` 拼接保序、`ParamParser` 按序处理，确定性有保证。判定为非问题。

---

## 小结

- 发现总数：7（P0: 0，P1: 0，P2: 3，P3: 4）。
- 最突出问题：`config_merger.go` 的 include 静默丢失（P2）与隐式合并语义（P2），二者共同影响多文件配置的可预测性；`bootstrap_resolver` 单点冗余丢失（P2）影响引导阶段可靠性。
- 整体评价：config 包解析健壮性（D5）与校验完整性良好，错误信息清晰可定位，patch 幂等性完备；主要改进空间集中在 D6 的合并/资源冲突处理的显式性与可观测性（合并语义文档化、空匹配告警、冗余保留）。
