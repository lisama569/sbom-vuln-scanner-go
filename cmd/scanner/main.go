// Command scanner scans local manifest/lock files against a local
// vulnerability database and prints deterministic JSON conclusions.
//
// Usage:
//
//	scanner --db vulns.json [--format auto|npm|gomod] [--workers N]
//	        [--exit-on-finding] FILE [FILE ...]
//
// Exit codes: 0 = all targets scanned, no findings; 1 = findings present;
// 2 = at least one target failed; 3 = usage/startup error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/lisama569/sbom-vuln-scanner-go/engine"
	_ "github.com/lisama569/sbom-vuln-scanner-go/parse/gomod"
	_ "github.com/lisama569/sbom-vuln-scanner-go/parse/npm"
	"github.com/lisama569/sbom-vuln-scanner-go/scan"
	"github.com/lisama569/sbom-vuln-scanner-go/vulndb"
)

func main() {
	var (
		dbPath  = flag.String("db", "", "path to local vulnerability database JSON")
		format  = flag.String("format", "auto", "manifest format: auto|npm|gomod")
		workers = flag.Int("workers", 4, "concurrent target workers")
		noFail  = flag.Bool("no-fail-on-finding", false, "exit 0 even when vulnerabilities are found")
	)
	flag.Parse()

	if *dbPath == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: scanner --db vulns.json [--format auto|npm|gomod] FILE ...")
		os.Exit(3)
	}

	db, err := vulndb.LoadFile(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "startup: %v\n", err)
		os.Exit(3)
	}

	targets, err := buildTargets(flag.Args(), *format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "startup: %v\n", err)
		os.Exit(3)
	}

	eng := engine.New(db, *workers)
	results := eng.ScanAll(context.Background(), targets)

	report := buildReport(db.Revision, results)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "output: %v\n", err)
		os.Exit(3)
	}

	if report.FailedTargets > 0 {
		os.Exit(2)
	}
	if report.TotalFindings > 0 && !*noFail {
		os.Exit(1)
	}
}

func buildTargets(files []string, format string) ([]scan.Target, error) {
	targets := make([]scan.Target, 0, len(files))
	for _, f := range files {
		fm := format
		if fm == "auto" {
			fm = detect(f)
		}
		switch fm {
		case "npm", "gomod":
		default:
			return nil, fmt.Errorf("cannot determine format for %q (use --format)", f)
		}
		targets = append(targets, scan.Target{Format: fm, Path: f})
	}
	return targets, nil
}

func detect(path string) string {
	switch filepath.Base(path) {
	case "package-lock.json":
		return "npm"
	case "go.mod":
		return "gomod"
	}
	return ""
}

type jsonReport struct {
	Revision      string       `json:"db_revision"`
	TotalFindings int          `json:"total_findings"`
	FailedTargets int          `json:"failed_targets"`
	Targets       []jsonTarget `json:"targets"`
}

type jsonTarget struct {
	Path       string        `json:"path"`
	Format     string        `json:"format"`
	Status     string        `json:"status"` // scanned | target_failed | internal
	Components int           `json:"components"`
	Rejected   int           `json:"rejected"`
	Warnings   int           `json:"warnings"`
	Findings   []jsonFinding `json:"findings,omitempty"`
	Failure    string        `json:"failure,omitempty"`
}

type jsonFinding struct {
	AdvisoryID   string `json:"advisory_id"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	Scope        string `json:"scope"`
	MatchedRange int    `json:"matched_range"`
	Reason       string `json:"reason"`
}

func buildReport(revision string, results []*scan.Result) jsonReport {
	r := jsonReport{Revision: revision}
	for _, res := range results {
		jt := jsonTarget{Path: res.Target.Path, Format: res.Target.Format}
		if res.Failure != nil {
			switch res.Failure.Class {
			case scan.FailureInternal:
				jt.Status = "internal"
			default:
				jt.Status = "target_failed"
			}
			jt.Failure = res.Failure.Error()
			r.FailedTargets++
		} else {
			jt.Status = "scanned"
			jt.Components = len(res.Manifest.Components)
			jt.Rejected = len(res.Manifest.Rejected)
			jt.Warnings = len(res.Manifest.Warnings)
			for _, f := range res.Findings {
				jt.Findings = append(jt.Findings, jsonFinding{
					AdvisoryID: f.AdvisoryID, Package: f.Package, Version: f.Version,
					Scope: f.Scope.String(), MatchedRange: f.MatchedRange, Reason: f.Reason})
				r.TotalFindings++
			}
		}
		r.Targets = append(r.Targets, jt)
	}
	// Deterministic ordering by path regardless of scheduling.
	sort.SliceStable(r.Targets, func(i, j int) bool { return r.Targets[i].Path < r.Targets[j].Path })
	return r
}
