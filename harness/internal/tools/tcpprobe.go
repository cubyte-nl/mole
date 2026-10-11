package tools

import (
	"context"
	"net"
	"strconv"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

const maxTCPProbePorts = 50

// TCPProbe does fast TCP connect checks against specific ports. It is the
// lightweight, nmap-free way to verify ports, and the gate is applied per
// port: ports outside the allowed list are reported as denied, not checked.
type TCPProbe struct{}

func (TCPProbe) Name() string   { return "tcp_probe" }
func (TCPProbe) Mutating() bool { return false }

func (TCPProbe) Description() string {
	return "Fast TCP connect check of specific in-scope host ports (no full scan). Use to verify a short list of ports."
}

func (TCPProbe) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"host":  map[string]any{"type": "string", "description": "In-scope host name or IP"},
			"ports": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Ports to check (max 50)"},
		},
		"required": []any{"host", "ports"},
	}
}

func (TCPProbe) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	host := strArg(args, "host")
	if host == "" {
		return core.Result{Tool: "tcp_probe", Allowed: false, Reason: "missing required argument 'host'"}
	}
	ports := intListArg(args, "ports")
	if len(ports) == 0 {
		return core.Result{Tool: "tcp_probe", Target: host, Allowed: false,
			Reason: "missing or empty 'ports' argument"}
	}
	truncated := false
	if len(ports) > maxTCPProbePorts {
		ports = ports[:maxTCPProbePorts]
		truncated = true
	}

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	checked := make([]map[string]any, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			checked = append(checked, map[string]any{"port": p, "open": false, "note": "invalid port"})
			continue
		}
		ok, reason := s.CheckTarget(ctx, host, &p)
		if !ok {
			checked = append(checked, map[string]any{"port": p, "open": false, "gate": reason})
			continue
		}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err == nil {
			conn.Close()
			checked = append(checked, map[string]any{"port": p, "open": true})
		} else {
			checked = append(checked, map[string]any{"port": p, "open": false, "note": err.Error()})
		}
	}
	payload := map[string]any{"host": host, "ports": checked}
	if truncated {
		payload["truncated"] = true
	}
	return core.Result{Tool: "tcp_probe", Target: host, Allowed: true, Payload: payload}
}

func intListArg(args map[string]any, key string) []int {
	v, ok := args[key]
	if !ok {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]int, 0, len(list))
	for _, item := range list {
		if n, ok := item.(float64); ok {
			out = append(out, int(n))
		}
	}
	return out
}
