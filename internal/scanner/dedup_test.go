package scanner

import (
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
)

func TestMergeSameNameDifferentVersionsKept(t *testing.T) {
	cs := []component.Component{
		{Ecosystem: component.EcoNpm, Name: "left-pad-lite", Version: "1.9.9", Relation: component.RelationDirect},
		{Ecosystem: component.EcoNpm, Name: "left-pad-lite", Version: "2.0.0", Relation: component.RelationIndirect},
		// 完全重复（同版本、直接+间接）应合并并升级关系。
		{Ecosystem: component.EcoNpm, Name: "left-pad-lite", Version: "1.9.9", Relation: component.RelationIndirect},
		// 跨生态同名包互不干扰。
		{Ecosystem: component.EcoPypi, Name: "left-pad-lite", Version: "1.9.9", Relation: component.RelationDirect},
	}
	out := MergeComponents(cs)
	t.Logf("原始输入 %d 条，归一化后 %d 条：", len(cs), len(out))
	for _, c := range out {
		t.Logf("判定依据: %s %s@%s relation=%s", c.Ecosystem, c.Name, c.Version, c.Relation)
	}
	if len(out) != 3 {
		t.Fatalf("归一化条数=%d 期望 3（npm 两个版本 + pypi 一个）", len(out))
	}
	for _, c := range out {
		if c.Ecosystem == component.EcoNpm && c.Name == "left-pad-lite" && c.Version == "1.9.9" {
			if c.Relation != component.RelationDirect {
				t.Errorf("1.9.9 重复出现应升级 direct，实际 %s", c.Relation)
			}
		}
	}

	// 多次合并结果必须逐条一致（确定性）。
	out2 := MergeComponents(cs)
	for i := range out {
		if out[i] != out2[i] {
			t.Fatalf("重复合并结果在第 %d 条漂移", i)
		}
	}
}
