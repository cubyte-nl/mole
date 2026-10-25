package tools

import (
	"context"
	"os/exec"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// Nmap runs a port scan with service version detection, and on request NSE
// scripts and OS detection for deeper enumeration.
type Nmap struct{}

func (Nmap) Name() string   { return "nmap" }
func (Nmap) Mutating() bool { return false }

func (Nmap) Description() string {
	return "Port scan with service version detection (nmap -Pn -sV) against an in-scope host; " +
		"optionally NSE service scripts (--script) and OS detection (-O) for deeper enumeration."
}

func (Nmap) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"host":    map[string]any{"type": "string", "description": "In-scope host name or IP"},
			"ports":   map[string]any{"type": "string", "description": `Optional port spec, e.g. "80,443" or "1-1024"`},
			"scripts": map[string]any{"type": "string", "description": `Optional NSE script spec for --script, e.g. "default", "safe" or "ssh2-enum-algos,http-title"`},
			"os":      map[string]any{"type": "boolean", "description": "Also attempt OS detection (-O); best with at least one open and one closed TCP port"},
		},
		"required": []any{"host"},
	}
}

func (Nmap) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	host := strArg(args, "host")
	if host == "" {
		return core.Result{Tool: "nmap", Allowed: false, Reason: "missing required argument 'host'"}
	}
	ports := strArg(args, "ports")
	scripts := strArg(args, "scripts")
	ok, reason := s.CheckTarget(ctx, host, portFromPorts(ports))
	if !ok {
		return core.Result{Tool: "nmap", Target: host, Allowed: false, Reason: reason}
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		return core.Result{Tool: "nmap", Target: host, Allowed: true,
			Reason: "nmap is not installed in this environment; port scanning is unavailable"}
	}
	cmdArgs := []string{"-Pn", "-sV"}
	if ports != "" {
		cmdArgs = append(cmdArgs, "-p", ports)
	}
	if scripts != "" {
		cmdArgs = append(cmdArgs, "--script", scripts)
	}
	if boolArg(args, "os") {
		cmdArgs = append(cmdArgs, "-O")
	}
	cmdArgs = append(cmdArgs, host)
	return runExternal(ctx, "nmap", "nmap", host, cmdArgs, 30*time.Minute)
}
