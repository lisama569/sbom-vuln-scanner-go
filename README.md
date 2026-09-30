# sbom-vuln-scanner-go

基于**本地漏洞库**的依赖成分扫描器：解析本地依赖清单/锁文件，归一化为统一成分模型，
再按漏洞库中的版本区间做匹配。不依赖任何网络服务，扫描结论可在本地完整复现。

## 支持的清单格式

| 格式 | 文件名 | 归一化要点 |
| --- | --- | --- |
| Go Modules | `go.mod` | `require` 单行/块写法；`// indirect` 注释标记传递依赖 |
| npm lockfile | `package-lock.json` | lockfileVersion 2/3 的 `packages` 映射；按 `node_modules/` 层数判定直接/间接，scoped 包与嵌套多版本副本均保留 |
| pip | `requirements*.txt` | `name[extras]==version` 钉选版本；支持续行、行内注释、环境标记、`-r/-e` 指令行识别 |

### 解析问题分类（绝不静默跳过）

每条无法正常归一化的记录都会以 `ParseIssue` 输出，附带**文件名、行号、原始输入文本**与可区分原因码：

| 代码 | 含义 | 级别 |
| --- | --- | --- |
| `invalid_version` | 版本字符串不符合语义化版本规范（如 `v1.2`、`01.2.3`） | 拒绝 |
| `missing_field` | 缺少包名/版本等必需字段（如 `six` 未钉选版本） | 拒绝 |
| `malformed_entry` | 条目结构不完整、无法解析 | 拒绝 |
| `non_pinned_specifier` | pip 非 `==` 算子（`>=`、`~=` 等），无法确定唯一成分版本 | 拒绝 |
| `unsupported_file` | 文件名不属于任何受支持格式 | 拒绝（目标失败） |
| `env_marker` | pip 环境标记（`; python_version < ...`），成分保留但提示其生效依赖环境 | 警告 |
| `directive` | pip 指令行（`-r`/`-e`/`-f`），不是依赖条目 | 警告 |

- **拒绝级**问题意味着有输入没有被完整扫描，整体结论不得判定为通过（目标状态 `rejected`）。
- **警告级**不阻断通过，但同样会被完整打印。

### 同一依赖重复出现的确定性结论

合并键为 `(生态, 名称, 版本)`：

- 同一依赖以**相同版本**同时出现在直接与传递依赖中 → 合并为一条，关系取 `direct` 优先；
- 同名但**不同版本**（npm 嵌套依赖常见）→ 各自保留，避免漏报其中任一版本；
- 跨生态同名包互不干扰；
- 合并结果按稳定键排序，与文件遍历、并发完成顺序无关。

## 版本匹配语义

严格按 [semver 2.0](https://semver.org/) 解析（允许 `v` 前缀），前导零、缺段、非法标识符一律拒绝。

漏洞库每条规则包含一个或多个 affected 区间，语义为**左闭右开** `[introduced, fixed)`：

- `introduced`：包含该边界；为空或 `"0"` 表示从 `0.0.0` 开始；
- `fixed`：**不包含**该边界——版本恰等于修复版本即为已修复；为空表示尚无修复版本（上界开放）；
- 多个区间取**并集**，适用于不连续的受影响版本段；
- **预发布版本**按 semver 优先级比较：`1.5.0-rc.1 < 1.5.0`，因此 fixed=1.5.0 时 `1.5.0-rc.1` 仍判定受影响（尚未达到修复版本）；
- 同一条 advisory 对同一成分最多产生一条命中，重叠区间不会重复计数。

每条命中都会打印：`advisory ID + 生态/包名@版本 + 直接/间接 + 命中的具体区间`，结论可逐条解释。

## 错误分类

| 类别 | 场景 | 对整体的影响 |
| --- | --- | --- |
| `target_failure` | 文件不存在/不可读、格式不支持、上下文取消 | 仅该目标失败，不污染其它目标 |
| `parse_error` | 解析器内部错误（如 JSON 结构性损坏）或 panic | 仅该目标失败；panic 会被 recover 并归类 |
| `fatal` | 漏洞库无法加载、扫描器配置非法（db 为 nil） | 中止整体扫描 |

并发扫描时每个目标相互隔离；**部分失败不视为整体通过**。结果严格按输入路径顺序返回。

## 结果缓存与结论复现

- 缓存键 = `目标路径 + 文件内容 SHA256 指纹 + 漏洞库 revision`，任一变化自动失效；
- 漏洞库 `revision` 是所有规则文件按文件名排序后联合计算的 SHA256 前缀。
  **规则文件不变 → revision 不变 → 同一份清单的历史结论保持一致**；规则更新后 revision 改变，
  旧结论不会被误用，且旧 revision 仍可在报告中追溯；
- 缓存只影响性能与可观测标记（`缓存=true/false`），命中与未命中返回的结论字节级一致；
- 并发顺序不影响最终结果（内部加锁，已通过 `-race` 验证）。

## 本地漏洞库格式

目录下每个 `*.json` 文件为一个规则数组（样例见 `testdata/advisories/advisories.json`）：

```json
[
  {
    "id": "GO-2024-0001",
    "ecosystem": "go",
    "package": "example.com/oldlib",
    "summary": "1.5.0 前存在越界读取",
    "affected": [
      { "introduced": "1.0.0", "fixed": "1.5.0" }
    ]
  }
]
```

`ecosystem` 取值：`go` / `npm` / `pypi`。加载时会校验区间版本合法性与区间是否倒置，
非法规则直接报错（避免规则静默失效）。

## 本地验证方法

```bash
# 构建
go build ./...

# 全量单测（含 -race 数据竞争检测）
go test -race -count=1 ./...

# 查看带原始输入与判定依据的详细测试日志
go test ./... -v

# 用仓库自带样例端到端扫描
go run ./cmd/sbom-scanner \
  -db testdata/advisories \
  testdata/samples/go.mod \
  testdata/samples/package-lock.json \
  testdata/samples/requirements.txt

# 重复扫描验证缓存（第二轮目标显示 缓存=true）
go run ./cmd/sbom-scanner -db testdata/advisories -repeat 2 \
  testdata/samples/go.mod testdata/samples/package-lock.json

# 关闭缓存
go run ./cmd/sbom-scanner -no-cache -db testdata/advisories testdata/samples/go.mod
```

退出码：`0` 全部通过；`1` 存在漏洞、拒绝级问题或失败目标；`2` 参数错误；`3` 致命错误。

### 测试覆盖的关键场景

- 畸形清单：缺字段、非法版本（含前导零/缺段）、结构损坏的 JSON、pip 指令与环境标记；
- 版本边界：introduced 包含、fixed 不包含、预发布 vs 修复版本、开放上界、多区间并集空洞；
- 并发重复扫描：20 个 goroutine 结论一致，输出顺序恒等于输入顺序；
- 缓存：同内容命中、文件修改失效、漏洞库 revision 变化失效；
- 错误分类：文件缺失、不支持格式、解析器内部错误三类可区分且互不污染。

## 代码结构

```
internal/semver      语义化版本解析、比较与区间/并集匹配
internal/component   统一成分模型、解析问题码与严重级别
internal/manifest    go.mod / package-lock.json / requirements.txt 解析器
internal/vuln        本地 JSON 漏洞库加载、revision 指纹、区间匹配
internal/scanner     成分合并去重、结果缓存、错误分类、并发扫描
cmd/sbom-scanner     CLI
testdata/            样例漏洞库与样例清单
```
