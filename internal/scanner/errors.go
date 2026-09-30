package scanner

import "fmt"

// ErrorKind 对扫描过程中的错误进行分类。
type ErrorKind string

const (
	// KindTargetFailure 单个目标自身失败（文件不存在、不可读、格式不支持等）。
	KindTargetFailure ErrorKind = "target_failure"
	// KindParseError 解析库内部报错（与可恢复的单条警告不同）。
	KindParseError ErrorKind = "parse_error"
	// KindFatal 致命错误（漏洞库不可用等全局问题），会中止整体扫描。
	KindFatal ErrorKind = "fatal"
)

// ScanError 携带分类的扫描错误。
type ScanError struct {
	Kind   ErrorKind
	Target string
	Err    error
}

func (e *ScanError) Error() string {
	if e == nil {
		return ""
	}
	if e.Target != "" {
		return fmt.Sprintf("%s [%s]: %v", e.Kind, e.Target, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Kind, e.Err)
}

func (e *ScanError) Unwrap() error { return e.Err }
