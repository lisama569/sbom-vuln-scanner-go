package vuln

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
)

// Database 是只读的本地漏洞库视图。
type Database interface {
	// Lookup 返回指定成分（生态+名称）的全部漏洞规则。
	Lookup(eco component.Ecosystem, name string) []Advisory
	// Revision 返回漏洞库内容版本（所有规则文件的有序哈希），
	// 用于缓存失效与历史结论复现。
	Revision() string
}

// LoadOptions 控制从本地目录加载漏洞库的行为。
type LoadOptions struct {
	Directory string
}

// advisoryJSON 是磁盘上单条漏洞规则的 JSON 表示。
type advisoryJSON struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Summary   string `json:"summary"`
	Affected  []struct {
		Introduced string `json:"introduced"`
		Fixed      string `json:"fixed"`
	} `json:"affected"`
}

type databaseFile struct {
	name string
	data []byte
}

// LoadDatabase 从本地目录加载 *.json 漏洞库文件（JSON 数组）并按 (生态,名称) 建索引。
// 规则文件按文件名排序后共同参与哈希，保证 revision 对内容变化稳定可复现。
func LoadDatabase(opts LoadOptions) (Database, error) {
	entries, err := os.ReadDir(opts.Directory)
	if err != nil {
		return nil, fmt.Errorf("读取漏洞库目录 %q 失败: %w", opts.Directory, err)
	}
	var files []databaseFile
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(opts.Directory, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("读取漏洞库文件 %q 失败: %w", e.Name(), err)
		}
		files = append(files, databaseFile{name: e.Name(), data: data})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })

	db := &memDatabase{byKey: make(map[string][]Advisory)}
	h := sha256.New()
	for _, f := range files {
		h.Write([]byte(f.name))
		h.Write(f.data)

		var records []advisoryJSON
		if err := json.Unmarshal(f.data, &records); err != nil {
			return nil, fmt.Errorf("漏洞库文件 %q 不是合法的 JSON 数组: %w", f.name, err)
		}
		for idx, rec := range records {
			adv, err := convertAdvisory(rec)
			if err != nil {
				return nil, fmt.Errorf("漏洞库文件 %q 第 %d 条规则非法: %w", f.name, idx, err)
			}
			key := advisoryKey(adv.Ecosystem, adv.PackageName)
			db.byKey[key] = append(db.byKey[key], adv)
		}
	}
	// 对每个键下的规则按 ID 排序，得到稳定的匹配顺序，避免重复计数/漏报受文件顺序影响。
	for k := range db.byKey {
		sort.Slice(db.byKey[k], func(i, j int) bool { return db.byKey[k][i].ID < db.byKey[k][j].ID })
	}
	db.revision = hex.EncodeToString(h.Sum(nil)[:12])
	return db, nil
}

func convertAdvisory(rec advisoryJSON) (Advisory, error) {
	if rec.ID == "" {
		return Advisory{}, fmt.Errorf("缺少 id")
	}
	eco := component.Ecosystem(rec.Ecosystem)
	switch eco {
	case component.EcoGoModules, component.EcoNpm, component.EcoPypi:
	default:
		return Advisory{}, fmt.Errorf("id=%s 的 ecosystem %q 不受支持", rec.ID, rec.Ecosystem)
	}
	if rec.Package == "" {
		return Advisory{}, fmt.Errorf("id=%s 缺少 package", rec.ID)
	}
	if len(rec.Affected) == 0 {
		return Advisory{}, fmt.Errorf("id=%s 缺少 affected 区间", rec.ID)
	}
	adv := Advisory{
		ID:          rec.ID,
		Ecosystem:   eco,
		PackageName: rec.Package,
		Summary:     rec.Summary,
	}
	for i, ar := range rec.Affected {
		if ar.Introduced != "" && ar.Introduced != "0" {
			if _, err := parseVer(ar.Introduced); err != nil {
				return Advisory{}, fmt.Errorf("id=%s affected[%d].introduced 非法: %w", rec.ID, i, err)
			}
		}
		if ar.Fixed != "" {
			if _, err := parseVer(ar.Fixed); err != nil {
				return Advisory{}, fmt.Errorf("id=%s affected[%d].fixed 非法: %w", rec.ID, i, err)
			}
		}
		if ar.Introduced != "" && ar.Fixed != "" {
			iv, _ := parseVer(orZero(ar.Introduced))
			fv, _ := parseVer(ar.Fixed)
			if cmpVer(iv, fv) >= 0 {
				return Advisory{}, fmt.Errorf("id=%s affected[%d] 区间为空或倒置: %s >= %s", rec.ID, i, ar.Introduced, ar.Fixed)
			}
		}
		adv.Ranges = append(adv.Ranges, AffectedRange{Introduced: ar.Introduced, Fixed: ar.Fixed})
	}
	return adv, nil
}

func orZero(s string) string {
	if s == "" {
		return "0.0.0"
	}
	return s
}

func advisoryKey(eco component.Ecosystem, name string) string {
	return string(eco) + "://" + name
}

type memDatabase struct {
	byKey    map[string][]Advisory
	revision string
}

func (d *memDatabase) Lookup(eco component.Ecosystem, name string) []Advisory {
	return d.byKey[advisoryKey(eco, name)]
}

func (d *memDatabase) Revision() string { return d.revision }
