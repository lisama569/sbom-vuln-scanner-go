package vuln

import "github.com/lisama569/sbom-vuln-scanner-go/internal/semver"

// parseVer / cmpVer 是 database 与 matcher 共享的版本辅助函数。
func parseVer(s string) (semver.Version, error) { return semver.Parse(s) }

func cmpVer(a, b semver.Version) int { return semver.Compare(a, b) }
