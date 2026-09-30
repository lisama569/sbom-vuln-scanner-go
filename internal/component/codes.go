package component

// 额外的解析问题类别（在四种基础类别之上补充 pip 特有情况）。
const (
	// IssueNonPinnedSpecifier 表示版本不是 == 钉选，无法确定唯一成分版本。
	IssueNonPinnedSpecifier IssueCode = "non_pinned_specifier"
	// IssueEnvMarker 表示条目带环境标记（; marker），是否生效取决于环境，
	// 仍归一为成分但必须给出可区分的警告。
	IssueEnvMarker IssueCode = "env_marker"
	// IssueDirective 表示 pip 指令行（-r/-e/-f 等），不是可归一的依赖条目。
	IssueDirective IssueCode = "directive"
)

// Severity 表示解析问题是否会导致对应条目无法被扫描。
type Severity string

const (
	// SeverityRejected 表示条目被拒绝、未参与漏洞匹配；存在此类问题时扫描不应判定为通过。
	SeverityRejected Severity = "rejected"
	// SeverityWarning 表示条目已归一或该行本就不是依赖，仅提示，不阻断通过。
	SeverityWarning Severity = "warning"
)

// SeverityOf 返回问题类别的严重级别。
func SeverityOf(code IssueCode) Severity {
	switch code {
	case IssueEnvMarker, IssueDirective:
		return SeverityWarning
	default:
		// invalid_version / missing_field / malformed_entry /
		// unsupported_file / non_pinned_specifier 均意味着有内容未被完整扫描。
		return SeverityRejected
	}
}
