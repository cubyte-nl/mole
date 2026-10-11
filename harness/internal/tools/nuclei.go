package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
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

func (Nuclei) Name() string   { return "nuclei" }
func (Nuclei) Mutating() bool { return true }

func (Nuclei) Description() string {
	return "Template-based vulnerability detection (nuclei) against an in-scope URL. " +
		"Vulnerability scanning: sends probes beyond passive scanning. Rate limited to 20 req/s."
}

func (Nuclei) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url":      map[string]any{"type": "string", "description": "In-scope target URL, e.g. https://host/path"},
			"tags":     map[string]any{"type": "string", "description": `Optional comma-separated template tags to run, e.g. "exposures,cve"`},
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
	cmdArgs := []string{"-u", parsed.String(), "-jsonl", "-no-color", "-silent", "-rate-limit", "20"}
	if tags != "" {
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

// trimNucleiOutput drops the raw HTTP request/response bodies nuclei emits for
// every match. They repeat whole response pages and bloat the model's context
// with no detection value — the template id, severity, matched-at and matcher
// name identify the finding. Lines that are not JSON findings (banners,
// warnings) pass through untouched.
func trimNucleiOutput(raw string) string {
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var finding map[string]any
		if json.Unmarshal([]byte(line), &finding) != nil {
			continue
		}
		delete(finding, "request")
		delete(finding, "response")
		if trimmed, err := json.Marshal(finding); err == nil {
			lines[i] = string(trimmed)
		}
	}
	return strings.Join(lines, "\n")
}
