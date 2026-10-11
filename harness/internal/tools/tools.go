// Package tools implements the gated recon tools. Every tool asks the scope
// gate before it touches a target; a denied target is reported back and never
// executed. The tools are exposed to the LLM as function calls, and can also
// be used directly.
//
// The tool interface, Result, and Registry plumbing live in the shared core
// (github.com/cubyte-nl/agent-core/tools, imported here as core). This package
// only declares MOLE's concrete tools and assembles them: reconnaissance tools
// are always available; vulnerability-scanning tools are only registered when
// the engagement has opted in.
package tools

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// NewRegistry builds the default set of tools over the scope boundary.
// Vulnerability-scanning tools (nuclei) are gated behind vulnScanning — they
// are the only mutating tools, so a reconnaissance engagement cannot reach
// them even if the model asks.
func NewRegistry(vulnScanning bool) *core.Registry[*scope.Scope] {
	return core.NewRegistry[*scope.Scope](vulnScanning,
		DNS{}, Nmap{}, HTTPProbe{}, TLSProbe{}, TCPProbe{}, SecurityHeaders{}, Subdomains{}, NoteOutOfScope{},
		Nuclei{},
	)
}

// runExternal executes an external binary against an in-scope target and
// returns the structured result; a non-zero exit is reported in Reason.
func runExternal(ctx context.Context, tool, bin, target string, args []string, timeout time.Duration) core.Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	res := core.Result{Tool: tool, Target: target, Allowed: true,
		Payload: map[string]any{
			"command": bin + " " + strings.Join(args, " "),
			"output":  string(out),
		}}
	if err != nil {
		res.Reason = fmt.Sprintf("%s exited: %v", tool, err)
	}
	return res
}

func strArg(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func intArg(args map[string]any, key string, def int) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case string:
			if i, err := strconv.Atoi(n); err == nil {
				return i
			}
		}
	}
	return def
}

// parseProbeURL normalises a user-supplied URL (adding http:// when the
// scheme is missing) and returns the parsed URL, the bare host, and the
// effective port (80/443 when the URL omits it).
func parseProbeURL(u string) (*url.URL, string, int, error) {
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return nil, "", 0, err
	}
	if parsed.Hostname() == "" {
		return nil, "", 0, fmt.Errorf("missing host")
	}
	port, _ := strconv.Atoi(parsed.Port())
	if port == 0 {
		if parsed.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return parsed, parsed.Hostname(), port, nil
}

// portFromPorts extracts a single port from a spec; nil for ranges, lists or
// empty input (those bypass the per-port gate check, as nmap does them itself).
func portFromPorts(ports string) *int {
	ports = strings.TrimSpace(ports)
	if ports == "" || strings.ContainsAny(ports, ",:-") {
		return nil
	}
	n, err := strconv.Atoi(ports)
	if err != nil || n < 1 || n > 65535 {
		return nil
	}
	return &n
}
