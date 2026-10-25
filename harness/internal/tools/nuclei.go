package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// Nuclei runs template-based vulnerability detection (nuclei) against an
// in-scope URL. This is the opt-in vulnerability-scanning tool: it sends
// probes beyond passive scanning. The rate limit is baked in, not left to
// the model.
type Nuclei struct{}

// defaultTags is the curated first-pass template set used when the model
// does not request specific tags. The full template set takes tens of
// minutes at the baked-in 20 req/s and would die inside the run budget;
// these three tags cover what a first pass usually needs.
const defaultTags = "exposures,cve,misconfig"

// excludedTags are always excluded: fuzz templates actively fuzz requests
// (the harness forbids fuzzing), antipattern templates are informational
// noise. Tech fingerprint templates (thousands of matches) are excluded
// on the default run too, to keep it fast and quiet.
const excludedTags = "fuzz,antipattern"

// allowedSeverities mirrors nuclei's severity levels so a typo is reported
// up front instead of silently producing an empty run.
var allowedSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// maxFindings caps the JSONL findings handed to the model: a template run
// can yield hundreds of matches and the model needs enough to act on, not
// all of them.
const maxFindings = 50

func (Nuclei) Name() string   { return "nuclei" }
func (Nuclei) Mutating() bool { return true }

func (Nuclei) Description() string {
	return "Template-based vulnerability detection (nuclei) against an in-scope URL. " +
		"Vulnerability scanning: sends probes beyond passive scanning. Rate limited to 20 req/s. " +
		"Without tags it runs a fast first pass (exposures, cve, misconfig); pass tags for a " +
		"targeted run. Fuzzing and antipattern templates are never run."
}

func (Nuclei) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url":      map[string]any{"type": "string", "description": "In-scope target URL, e.g. https://host/path"},
			"tags":     map[string]any{"type": "string", "description": `Optional comma-separated template tags to run, e.g. "exposures,cve"; omit for the default first pass (exposures,cve,misconfig)`},
			"severity": map[string]any{"type": "string", "description": "Optional minimum finding severity: info, low, medium, high, critical"},
		},
		"required": []any{"url"},
	}
}

func (Nuclei) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	urlStr := strArg(args, "url")
	if urlStr == "" {
		return core.Result{Tool: "nuclei", Allowed: false, Reason: "missing required argument 'url'"}
	}
	tags := strArg(args, "tags")
	severity := strArg(args, "severity")
	if severity != "" && !allowedSeverities[strings.ToLower(severity)] {
		return core.Result{Tool: "nuclei", Target: urlStr, Allowed: false,
			Reason: "invalid severity: expected info, low, medium, high or critical"}
	}
	parsed, host, port, err := parseProbeURL(urlStr)
	if err != nil {
		return core.Result{Tool: "nuclei", Target: urlStr, Allowed: false, Reason: fmt.Sprintf("invalid URL: %v", err)}
	}
	ok, reason := s.CheckTarget(ctx, host, &port)
	if !ok {
		return core.Result{Tool: "nuclei", Target: host, Allowed: false, Reason: reason}
	}
	if _, err := exec.LookPath("nuclei"); err != nil {
		return core.Result{Tool: "nuclei", Target: host, Allowed: true,
			Reason: "nuclei is not installed in this environment; vulnerability scanning is unavailable"}
	}
	excludes := excludedTags
	if tags == "" {
		excludes += ",tech"
	}
	cmdArgs := []string{"-u", parsed.String(), "-jsonl", "-no-color", "-silent",
		"-rate-limit", "20", "-timeout", "10", "-etags", excludes}
	if tags == "" {
		cmdArgs = append(cmdArgs, "-tags", defaultTags)
	} else {
		cmdArgs = append(cmdArgs, "-tags", tags)
	}
	if severity != "" {
		cmdArgs = append(cmdArgs, "-severity", severity)
	}
	res := runExternal(ctx, "nuclei", "nuclei", host, cmdArgs, 15*time.Minute)
	if p, ok := res.Payload.(map[string]any); ok {
		if out, ok := p["output"].(string); ok {
			p["output"] = trimNucleiOutput(out)
		}
	}
	return res
}

// trimNucleiOutput drops the raw HTTP request/response bodies nuclei emits
// for every match. They repeat whole response pages and bloat the model's
// context with no detection value — the template id, severity, matched-at
// and matcher name identify the finding. Lines that are not JSON findings
// (banners, warnings) pass through untouched. Findings are deduplicated per
// template+target (one line per matcher would fill the cap), ordered
// most-severe first, and capped at maxFindings.
func trimNucleiOutput(raw string) string {
	type finding struct {
		data    map[string]any
		sevRank int
	}
	var banners []string
	var findings []finding
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f map[string]any
		if json.Unmarshal([]byte(line), &f) != nil {
			banners = append(banners, line)
			continue
		}
		delete(f, "request")
		delete(f, "response")
		findings = append(findings, finding{f, severityRank(f)})
	}
	// The same template hitting the same target once per matcher yields N
	// near-identical lines; keep one and aggregate the matcher names.
	seen := map[string]int{}
	deduped := make([]finding, 0, len(findings))
	for _, f := range findings {
		key := dedupeKey(f.data)
		if j, ok := seen[key]; ok {
			mergeMatchers(deduped[j].data, f.data)
			continue
		}
		seen[key] = len(deduped)
		deduped = append(deduped, f)
	}
	findings = deduped
	sort.SliceStable(findings, func(a, b int) bool { return findings[a].sevRank < findings[b].sevRank })
	var out []string
	out = append(out, banners...)
	if len(findings) > maxFindings {
		out = append(out, fmt.Sprintf("… %d lower-severity finding(s) trimmed; re-run with narrower tags for the full list",
			len(findings)-maxFindings))
		findings = findings[:maxFindings]
	}
	for _, f := range findings {
		if trimmed, err := json.Marshal(f.data); err == nil {
			out = append(out, string(trimmed))
		}
	}
	return strings.Join(out, "\n")
}

// dedupeKey identifies "same template on same target" findings.
func dedupeKey(f map[string]any) string {
	id, _ := f["template-id"].(string)
	matched, _ := f["matched-at"].(string)
	if matched == "" {
		matched, _ = f["url"].(string)
	}
	return id + "\x00" + matched
}

// mergeMatchers appends a duplicate finding's matcher name to the kept
// finding's comma-separated list, preserving all observed matchers.
func mergeMatchers(kept, extra map[string]any) {
	name, _ := extra["matcher-name"].(string)
	if name == "" {
		return
	}
	have, _ := kept["matcher-name"].(string)
	for _, existing := range strings.Split(have, ",") {
		if strings.TrimSpace(existing) == name {
			return
		}
	}
	if have == "" {
		kept["matcher-name"] = name
	} else {
		kept["matcher-name"] = have + ", " + name
	}
}

// severityRank orders findings for the cap: most severe first. Nuclei
// reports severity under info.severity (older releases: top-level "severity").
func severityRank(f map[string]any) int {
	sev, _ := f["severity"].(string)
	if info, ok := f["info"].(map[string]any); ok {
		if s, ok := info["severity"].(string); ok {
			sev = s
		}
	}
	switch strings.ToLower(sev) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}
