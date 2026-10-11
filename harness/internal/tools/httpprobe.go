package tools

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// HTTPProbe performs a GET against an in-scope URL.
type HTTPProbe struct{}

func (HTTPProbe) Name() string   { return "http_probe" }
func (HTTPProbe) Mutating() bool { return false }

func (HTTPProbe) Description() string {
	return "HTTP(S) GET against an in-scope URL; returns status, response headers and the start of the body."
}

func (HTTPProbe) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{"type": "string", "description": "Full URL (scheme optional, defaults to http)"},
		},
		"required": []any{"url"},
	}
}

func (HTTPProbe) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	u := strArg(args, "url")
	if u == "" {
		return core.Result{Tool: "http_probe", Allowed: false, Reason: "missing required argument 'url'"}
	}
	parsed, host, port, err := parseProbeURL(u)
	if err != nil {
		return core.Result{Tool: "http_probe", Target: u, Allowed: false, Reason: "invalid URL: " + err.Error()}
	}
	ok, reason := s.CheckTarget(ctx, host, &port)
	if !ok {
		return core.Result{Tool: "http_probe", Target: u, Allowed: false, Reason: reason}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return core.Result{Tool: "http_probe", Target: u, Allowed: true, Reason: "building request: " + err.Error()}
	}
	req.Header.Set("User-Agent", "mole-recon")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return core.Result{Tool: "http_probe", Target: u, Allowed: true, Reason: "request failed: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	headers := map[string]string{}
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}
	return core.Result{Tool: "http_probe", Target: u, Allowed: true,
		Payload: map[string]any{
			"status":     resp.StatusCode,
			"headers":    headers,
			"body_start": string(body),
		}}
}
