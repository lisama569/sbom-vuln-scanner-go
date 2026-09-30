# 本地依赖成分漏洞扫描器（Go）

基于**本地漏洞库**对**本地清单/锁文件**做依赖成分扫描。扫描结论可以落到具体的
依赖项（包名、版本、直接/传递）和具体漏洞条目（advisory ID、命中的区间组、逐条
边界判定依据），全程离线、确定性、可本地复现。

只依赖 Go 标准库（Go 1.25）。

## 支持的清单格式

| 格式 (`--format`) | 文件 | 说明 |
|---|---|---|
| `npm` | `package-lock.json` | lockfileVersion 1（`dependencies` 树）、2/3（`packages` 映射）。`auto` 探测按文件名识别。 |
| `gomod` | `go.mod` | 解析 `require`（单行与 `require ( ... )` 块）、`replace` 版本改写；`module`/`go` 指令忽略。 |

所有格式解析后归一到统一成分模型（`component.Component`）：

```
ID    = ecosystem:name@version   // 成分实例标识
Key   = ecosystem:name           // 包标识（忽略版本）
scope = direct | transitive
```

### 归一化与去重规则（确定性）

- 同一 `ID`（名+版本完全相同）在直接依赖与传递依赖中重复出现时：**合并为一条，
  作用域取 direct（direct wins）**，`DependsOn` 取并集，并产生 `scope_dedup`
  警告——合并不是静默的。
- 同一个包名被锁到**不同版本**时：**不合并**，每个版本都是独立成分（多版本共存是
  合法的依赖树事实），同时产生 `multiple_versions` 警告；后续漏洞匹配对每个版本
  独立评估，因此既不会漏报某个钉住版本，也不会把同一漏洞重复计数到同一成分实例。
- 成分按 `(name, version)` 稳定排序；拒绝记录按 `(file, line)` 排序；输出顺序与
  文件内顺序、并发调度无关。
- npm 的 workspace/软链条目（`"link": true`）不是已发布包，产生 `link_skipped`
  警告后跳过；`name` 字段与 `node_modules` 路径不一致时以路径为准并产生
  `name_path_mismatch` 警告。
- gomod 的 `replace old => new vX` 会把生效版本替换为 `vX`，并产生
  `replace_version` 警告（原始版本写在警告详情里）。
- 所有版本在校验通过后统一存为规范 semver（去掉允许的前导 `v`，
  如 `v1.2.3` → `1.2.3`）。

### 字段缺失 / 非法版本 / 结构不完整：拒绝原因可区分

解析器**不会静默丢弃**任何无法归一的记录，它们进入 `Manifest.Rejected`，原因码互
不相同：

| 原因码 | 触发场景 |
|---|---|
| `missing_name` | npm 无法从 `packages` 键推导包名且无 `name`；gomod 模块路径非法 |
| `missing_version` | 记录存在但版本为空 |
| `invalid_version` | 版本字符串不符合 semver（含前导零、标识符非法等） |
| `malformed_entry` | 条目结构不完整（如 gomod `require` 只有一个字段） |
| `unsupported_format` | 保留给格式级不支持 |

每条拒绝记录都带有 `Source(file/line 或 node_modules 原始键)` 与 `Raw`（原始记录
摘要/原始行文本），单测日志会打印原始输入与判定依据，便于复现。

整个文件根本无法作为该格式读取时（JSON 语法损坏、缺少 v1/v2 两套必需结构、
go.mod 未闭合块、文件不存在），返回目标级错误（见下“错误分类”），而不是逐记录
拒绝。

## 版本匹配语义

版本与区间实现遵循 <https://semver.org>（`semver` 包）：

- 核心 `MAJOR.MINOR.PATCH`，前导零非法（`01.0.0` 拒绝）；允许一个前导 `v`。
- **预发布版本按纯 semver 优先级参与比较**：`1.5.0-alpha < 1.5.0`。因此
  `>=1.0.0 <1.5.0` 会命中 `1.5.0-alpha`（修复版发布前的预发布仍在受影响区间内），
  而不命中 `1.0.0-alpha`。构建元数据（`+build`）不影响优先级。
- 区间表达式语法：

  ```
  constraint = group { "||" group }     # 多区间并集（OR）
  group      = bound { 空白 bound }     # 交集（AND）
  bound      = [op] version             # 省略 op 即 "="
  op ∈ =  !=  >  >=  <  <=
  ```

  操作符可与版本粘连（`>=1.0.0`）也可分写（`>= 1.0.0`）。
- **边界语义**：`>=`/`<=` 含边界，`>`/`<` 不含；`= x` 精确，`!= x` 排除单点。
- **多区间并集**：任一组全部成立即命中；记录返回首个命中组的序号（0 基
  `matched_range`）。
- **已修复版本（fixed in）**：漏洞库中以开区间上界表达，例如“1.5.0 修复”写作
  `>=下界 <1.5.0`，于是 `1.5.0` 本身不命中、`1.5.0-alpha` 命中。
- 每条结论的 `Reason` 是逐边界的可解释证据，例如：

  ```
  version 1.1.0 satisfies >=1.0.0 <1.2.0 (group #1):
    >=1.0.0(1.1.0)=true AND <1.2.0(1.1.0)=true; advisory=GO-2024-2001 ...
  ```

## 本地漏洞库格式

JSON 文件（示例：`testdata/e2e/vulns.json`）：

```json
{
  "revision": "2024-09-01-local",
  "advisories": [
    {
      "id": "CVE-2024-1001",
      "ecosystem": "npm",
      "package": "left-pad",
      "summary": "RCE in left-pad",
      "affected": [
        [ {"op": ">=", "version": "1.0.0"}, {"op": "<", "version": "1.5.0"} ]
      ]
    }
  ]
}
```

- `affected` 是“区间组的数组”：每个组是边界数组（组内 AND，组间 OR）。
- 加载时全量校验：缺 id/ecosystem/package、重复 id、空区间、未知操作符、非法边界
  版本都会让**整个漏洞库被拒绝**，绝不部分生效（`vulndb.LoadFile/LoadFS`）。
- **可复现性**：每个扫描结果携带 `db_revision`。漏洞库可显式写 `revision`；不写
  时自动回退为文件内容的 `sha256:` 前缀。于是“同一份清单 + 同一 revision”⇔“同一
  结论”；规则文件更新后，历史报告凭其 revision 仍能被识别与复现（见
  `integration/scan_test.go` 的 `TestIntegration_ReproducibleByRevision`）。

## 错误分类（三级，可区分）

| 层级 | 类别 | 含义 | 例子 |
|---|---|---|---|
| 记录级 | `component.Rejected`（非致命） | 单条记录无法归一，其他记录照常扫描 | 非法版本、缺名、结构不完整 |
| 目标级 | `scan.FailureTarget`（`status:"target_failed"`） | 该目标本身无法处理；**不污染其它目标** | 文件不存在、JSON 损坏、未知格式、未闭合块 |
| 系统级 | `scan.FailureInternal`（`status:"internal"`） | 解析器/匹配器内部异常，与坏输入区分 | 解析器 panic（被 recover 归类）、nil 漏洞库、库规则非法导致匹配异常 |

解析器自己的错误在 `parse.Error.Class` 上进一步区分 `parse_failed` 与 `internal`。

**部分失败绝不当成整体通过**：引擎返回每个目标独立的 `Result`；CLI 只要有目标失
败就以退出码 2 结束；有漏洞命中则退出码 1；全干净才是 0。

## 并发、缓存与失效语义（`engine` 包）

- 多目标并发（worker 信号量，`--workers`），**结果始终按输入顺序返回**。
- 同一目标键（`format:path`）：
  - 跨次调用命中结果缓存；
  - 同一次 `ScanAll` 中并发重复请求走 **single-flight**，实际解析只发生一次，所有
    请求拿到同一个 `*Result`（结论逐字节一致，不存在重复计数）。
- `Invalidate(targets...)` 使指定目标缓存失效，无参则清空全部。实现上采用**单调
  递增的 generation**：失效时代数递增，正在飞行中的扫描结束后不会把旧结果写回，
  等待者观察到代数变化会在新代数下重扫一次——缓存命中与失效都不会改变最终结论。
- 缓存命中/未命中计数通过 `engine.Stats()` 暴露，供测试断言。

## 本地验证方法

```bash
# 1. 全量单测（含 -race）
go test ./... -race -v

# 2. 端到端 CLI
go run ./cmd/scanner \
  --db testdata/e2e/vulns.json \
  testdata/e2e/package-lock.json testdata/e2e/go.mod
echo $?   # 1 = 有漏洞命中；2 = 有目标失败；0 = 干净

# 指定格式 / 并发度；找到漏洞也返回 0（用于只看报告的场景）
go run ./cmd/scanner --db DB.json --format npm --workers 8 --no-fail-on-finding lock.json
```

`testdata/e2e/` 下提供了可直接复现的样例：含区间边界版本、预发布版本
（`1.5.0-alpha`）、多区间并集（命中/未命中各一）、非法版本拒绝、link 条目警告、
跨生态（npm + gomod）命中。

关键测试索引：

- 版本边界/预发布/多区间：`semver/constraint_test.go`、`match/match_test.go`
- 畸形清单与可区分拒绝原因：`parse/npm/npm_test.go`、`parse/gomod/gomod_test.go`
- 并发重复扫描 / 单飞 / 缓存失效 / 失败隔离：`engine/engine_test.go`（`-race`）
- 历史结论按 revision 复现、规则更新后结论可区分：`integration/scan_test.go`

测试日志使用 `-v` 时会打印**原始输入**（原始 lock/go.mod/DB 片段）与**归一化后的
判定依据**（成分 ID、作用域、拒绝原因与原始记录、逐条区间边界证据）。

## 包结构

```
component/  统一成分模型、拒绝/警告记录
semver/     semver 解析、优先级、约束区间
vulndb/     本地漏洞库加载、校验、revision
parse/      解析器接口、错误分类、确定性归一化/去重
parse/npm   package-lock.json (v1/v2/v3)
parse/gomod go.mod
match/      区间匹配、单次计数、可解释证据、稳定排序
scan/       单目标编排、三级错误分类、结果携带 revision
engine/     并发 + 缓存 + single-flight + generation 失效
cmd/scanner CLI（确定性 JSON 报告）
integration/ 端到端场景
```
