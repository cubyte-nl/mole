package tools

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// SecurityHeaders fetches an in-scope URL and evaluates common security
// response headers, returning a verdict per header so findings are consistent
// across runs instead of being eyeballed out of raw headers.
type SecurityHeaders struct{}

func (SecurityHeaders) Name() string   { return "security_headers" }
func (SecurityHeaders) Mutating() bool { return false }

func (SecurityHeaders) Description() string {
	return "Fetch an in-scope URL and evaluate security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy, cookie flags) with a verdict per header."
}

func (SecurityHeaders) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{"type": "string", "description": "Full URL (scheme optional, defaults to http)"},
		},
		"required": []any{"url"},
	}
}

// newProbeClient builds the HTTP client; a variable so tests can inject
// transport configuration (e.g. trust a local test certificate).
var newProbeClient = func() *http.Client {
	return &http.Client{Timeout: 20 * time.Second}
}

func (SecurityHeaders) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	u := strArg(args, "url")
	if u == "" {
		return core.Result{Tool: "security_headers", Allowed: false, Reason: "missing required argument 'url'"}
	}
	parsed, host, port, err := parseProbeURL(u)
	if err != nil {
		return core.Result{Tool: "security_headers", Target: u, Allowed: false, Reason: "invalid URL: " + err.Error()}
	}
	ok, reason := s.CheckTarget(ctx, host, &port)
	if !ok {
		return core.Result{Tool: "security_headers", Target: u, Allowed: false, Reason: reason}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return core.Result{Tool: "security_headers", Target: u, Allowed: true, Reason: "building request: " + err.Error()}
	}
	req.Header.Set("User-Agent", "mole-recon")
	client := newProbeClient()
	resp, err := client.Do(req)
	if err != nil {
		return core.Result{Tool: "security_headers", Target: u, Allowed: true, Reason: "request failed: " + err.Error()}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	secure := parsed.Scheme == "https"
	checks := []map[string]any{
		checkHSTS(resp.Header.Get("Strict-Transport-Security"), secure),
		checkCSP(resp.Header.Get("Content-Security-Policy")),
		checkFrame(resp.Header, resp.Header.Get("Content-Security-Policy")),
		checkPresent("X-Content-Type-Options", resp.Header.Get("X-Content-Type-Options"), "nosniff"),
		checkPresent("Referrer-Policy", resp.Header.Get("Referrer-Policy"), ""),
		checkPresent("Permissions-Policy", resp.Header.Get("Permissions-Policy"), ""),
		checkCookies(resp.Header.Values("Set-Cookie")),
	}
	return core.Result{Tool: "security_headers", Target: u, Allowed: true,
		Payload: map[string]any{
			"status":    resp.StatusCode,
			"final_url": resp.Request.URL.String(),
			"checks":    checks,
		}}
}

func checkHSTS(v string, secure bool) map[string]any {
	if v == "" {
		verdict := "missing"
		if !secure {
			verdict = "info"
		}
		return map[string]any{"header": "Strict-Transport-Security", "present": false, "verdict": verdict}
	}
	if !secure {
		return map[string]any{"header": "Strict-Transport-Security", "present": true, "value": v,
			"verdict": "weak", "note": "HSTS on plaintext HTTP is ignored by browsers"}
	}
	low := strings.ToLower(v)
	maxAge := 0
	for _, part := range strings.Split(low, ";") {
		if k, val, found := strings.Cut(strings.TrimSpace(part), "="); found && strings.TrimSpace(k) == "max-age" {
			maxAge, _ = strconv.Atoi(strings.TrimSpace(val))
			break
		}
	}
	var notes []string
	if maxAge < 31536000 {
		notes = append(notes, "max-age below one year")
	}
	if !strings.Contains(low, "includesubdomains") {
		notes = append(notes, "no includeSubDomains")
	}
	if !strings.Contains(low, "preload") {
		notes = append(notes, "no preload")
	}
	verdict := "ok"
	if len(notes) > 0 {
		verdict = "weak"
	}
	out := map[string]any{"header": "Strict-Transport-Security", "present": true, "value": v, "verdict": verdict}
	if len(notes) > 0 {
		out["note"] = strings.Join(notes, "; ")
	}
	return out
}

func checkCSP(v string) map[string]any {
	if v == "" {
		return map[string]any{"header": "Content-Security-Policy", "present": false, "verdict": "missing"}
	}
	return map[string]any{"header": "Content-Security-Policy", "present": true, "value": truncate(v, 200), "verdict": "ok"}
}

func checkFrame(h http.Header, csp string) map[string]any {
	if v := h.Get("X-Frame-Options"); v != "" {
		return map[string]any{"header": "X-Frame-Options", "present": true, "value": v, "verdict": "ok"}
	}
	if strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		return map[string]any{"header": "X-Frame-Options", "present": true,
			"verdict": "ok", "note": "clickjacking protection via CSP frame-ancestors"}
	}
	return map[string]any{"header": "X-Frame-Options", "present": false,
		"verdict": "missing", "note": "no X-Frame-Options and no CSP frame-ancestors"}
}

func checkPresent(header, v, want string) map[string]any {
	if v == "" {
		return map[string]any{"header": header, "present": false, "verdict": "missing"}
	}
	if want != "" && !strings.Contains(strings.ToLower(v), strings.ToLower(want)) {
		return map[string]any{"header": header, "present": true, "value": truncate(v, 200),
			"verdict": "weak", "note": "present but does not set " + want}
	}
	return map[string]any{"header": header, "present": true, "value": truncate(v, 200), "verdict": "ok"}
}

func checkCookies(cookies []string) map[string]any {
	if len(cookies) == 0 {
		return map[string]any{"header": "Set-Cookie", "present": false, "verdict": "info", "note": "no cookies set"}
	}
	var issues []string
	for _, c := range cookies {
		low := strings.ToLower(c)
		name := c
		if i := strings.Index(c, ";"); i > 0 {
			name = strings.TrimSpace(c[:i])
		}
		if !strings.Contains(low, "secure") {
			issues = append(issues, name+": no Secure flag")
		}
		if !strings.Contains(low, "httponly") {
			issues = append(issues, name+": no HttpOnly flag")
		}
		if !strings.Contains(low, "samesite") {
			issues = append(issues, name+": no SameSite flag")
		}
	}
	out := map[string]any{"header": "Set-Cookie", "present": true,
		"cookies": len(cookies), "verdict": "ok"}
	if len(issues) > 0 {
		out["verdict"] = "weak"
		out["note"] = strings.Join(issues, "; ")
	}
	return out
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n] + "…"
}
