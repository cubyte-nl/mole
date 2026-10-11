package tools

import (
	"context"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// DNS resolves host names to addresses.
type DNS struct{}

func (DNS) Name() string   { return "dns_lookup" }
func (DNS) Mutating() bool { return false }

func (DNS) Description() string {
	return "Resolve a host name or IP to its addresses. Useful as a first step to see what a target is."
}

func (DNS) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"host": map[string]any{"type": "string", "description": "Host name or IP address"},
		},
		"required": []any{"host"},
	}
}

func (DNS) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	host := strArg(args, "host")
	if host == "" {
		return core.Result{Tool: "dns_lookup", Allowed: false, Reason: "missing required argument 'host'"}
	}
	ok, reason := s.CheckTarget(ctx, host, nil)
	if !ok {
		return core.Result{Tool: "dns_lookup", Target: host, Allowed: false, Reason: reason}
	}
	addrs, err := s.Resolve(ctx, host)
	if err != nil {
		return core.Result{Tool: "dns_lookup", Target: host, Allowed: true,
			Reason: "resolution failed: " + err.Error()}
	}
	return core.Result{Tool: "dns_lookup", Target: host, Allowed: true,
		Payload: map[string]any{"addresses": addrs}}
}
