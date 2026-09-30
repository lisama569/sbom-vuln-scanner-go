package vuln

import "github.com/lisama569/sbom-vuln-scanner-go/internal/component"

// fakeMemDB 供其它包测试使用的内存漏洞库。
type fakeMemDB struct {
	data     map[string][]Advisory
	revision string
}

func (d *fakeMemDB) Lookup(eco component.Ecosystem, name string) []Advisory {
	return d.data[string(eco)+"://"+name]
}
func (d *fakeMemDB) Revision() string { return d.revision }

// MustNewFakeDB 用给定 advisory 构造内存漏洞库，仅供测试。
func MustNewFakeDB(revision string, advs []Advisory) Database {
	d := &fakeMemDB{data: map[string][]Advisory{}, revision: revision}
	for _, a := range advs {
		k := string(a.Ecosystem) + "://" + a.PackageName
		d.data[k] = append(d.data[k], a)
	}
	return d
}
