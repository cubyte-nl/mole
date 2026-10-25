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

// httpRequestCap caps the response body returned to the model (8 KB: enough
// to inspect reflection and forms, small enough to keep the context bounded).
const httpRequestCap = 8192

// httpRequestTimeout bounds a single request; validation probes never need
// more.
const httpRequestTimeout = 30 * time.Second

// httpMethods is the allowlist for the method argument. Anything else is
// rejected: the tool is for validation, not for arbitrary abuse.
var httpMethods = map[string]bool{
	http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodHead: true,
	http.MethodOptions: true,
}

// HTTPRequest performs a model-directed HTTP(S) request against an in-scope
// URL. It exists for the probes http_probe (GET-only, fixed) cannot express:
// crafted GET query strings, POST forms (uploads, logins), and custom
// headers. It is mutating (it can change target state, e.g. submitting a
// form), so it is registered only for vulnerability-scanning engagements,
// and every request is rate-limited per host in code.
type HTTPRequest struct{}

func (HTTPRequest) Name() string   { return "http_request" }
func (HTTPRequest) Mutating() bool { return true }

func (HTTPRequest) Description() string {
	return "HTTP(S) request with arbitrary method, headers and body against an in-scope URL; " +
		"returns status, headers and the start of the body. Use it for crafted validation probes " +
		"that http_probe (GET-only) cannot express, e.g. POSTing a form. Payloads must be " +
		"non-destructive; requests are rate-limited in code."
}

func (HTTPRequest) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url":    map[string]any{"type": "string", "description": "Full URL (scheme optional, defaults to http)"},
			"method": map[string]any{"type": "string", "description": "HTTP method; one of GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS (default GET)"},
			"headers": map[string]any{"type": "object", "description": "Extra request headers as an object of string values",
				"additionalProperties": map[string]any{"type": "string"}},
			"body": map[string]any{"type": "string", "description": "Request body (ignored for GET and HEAD); sent as " +
				"application/x-www-form-urlencoded unless Content-Type is given in headers"},
		},
		"required": []any{"url"},
	}
}

func (HTTPRequest) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	const name = "http_request"
	u := strArg(args, "url")
	if u == "" {
		return core.Result{Tool: name, Allowed: false, Reason: "missing required argument 'url'"}
	}
	parsed, host, port, err := parseProbeURL(u)
	if err != nil {
		return core.Result{Tool: name, Target: u, Allowed: false, Reason: "invalid URL: " + err.Error()}
	}
	ok, reason := s.CheckTarget(ctx, host, &port)
	if !ok {
		return core.Result{Tool: name, Target: u, Allowed: false, Reason: reason}
	}
	method := strings.ToUpper(strArg(args, "method"))
	if method == "" {
		method = http.MethodGet
	}
	if !httpMethods[method] {
		return core.Result{Tool: name, Target: u, Allowed: false,
			Reason: "method must be one of GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS"}
	}
	body := strArg(args, "body")
	if method == http.MethodGet || method == http.MethodHead {
		body = ""
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), reader)
	if err != nil {
		return core.Result{Tool: name, Target: u, Allowed: false, Reason: "building request: " + err.Error()}
	}
	req.Header.Set("User-Agent", "mole-web")
	for k, v := range stringMapArg(args, "headers") {
		req.Header.Set(k, v)
	}
	// Form-style default (like curl --data): without a Content-Type most
	// backends (notably PHP) never parse the body, so $_POST stays empty and
	// the request silently does nothing.
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if err := webLimiter.Wait(ctx, host); err != nil {
		return core.Result{Tool: name, Target: u, Allowed: true, Reason: "rate limit: " + err.Error()}
	}
	client := &http.Client{Timeout: httpRequestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return core.Result{Tool: name, Target: u, Allowed: true, Reason: "request failed: " + err.Error()}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, httpRequestCap))
	headers := map[string]string{}
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}
	return core.Result{Tool: name, Target: u, Allowed: true,
		Payload: map[string]any{
			"status":     resp.StatusCode,
			"headers":    headers,
			"body_start": string(respBody),
		}}
}

// stringMapArg reads a map-typed argument ('headers', 'fields') as a map of
// string values, tolerating JSON numbers and booleans some backends emit.
func stringMapArg(args map[string]any, key string) map[string]string {
	raw, ok := args[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch s := v.(type) {
		case string:
			out[k] = s
		case float64:
			out[k] = strconv.FormatFloat(s, 'f', -1, 64)
		case bool:
			out[k] = strconv.FormatBool(s)
		}
	}
	return out
}
