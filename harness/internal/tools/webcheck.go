package tools

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// webcheckCap caps each probe response kept for comparison and evidence.
const webcheckCap = 8192

// webcheckTimeout bounds one probe request.
const webcheckTimeout = 20 * time.Second

// webcheckClasses is the allowlist for the class argument.
var webcheckClasses = map[string]bool{
	"sqli": true, "lfi": true, "rfi": true, "cmdi": true,
	"xss": true, "upload": true, "idor": true,
}

// probeSpec is one query-value variant of the parameter under test.
type probeSpec struct {
	Name  string
	Value string
}

// probeOutcome is the observed response of one probe.
type probeOutcome struct {
	Name   string
	Status int
	Body   string
	Err    string // non-empty when the request itself failed
}

// WebCheck validates one web input (a URL plus the parameter name) for one
// core bug class with fixed, non-destructive payloads. The model picks the
// URL and parameter; the tool picks the payloads, so no destructive payload
// can reach the target through this tool. GET-class probes rewrite the query
// value of the named parameter; the upload class POSTs one fixed harmless
// text file to the named file field and fetches it back. Every request is
// rate-limited per host in code. It is mutating (upload writes a file; the
// probes exercise input handling) and is registered only for
// vulnerability-scanning engagements.
type WebCheck struct{}

func (WebCheck) Name() string   { return "web_check" }
func (WebCheck) Mutating() bool { return true }

func (WebCheck) Description() string {
	return "Validate one web input for one core bug class — sqli, lfi, rfi, cmdi, xss, upload, idor — " +
		"using fixed non-destructive payloads. Takes the page URL and the parameter name; the tool " +
		"chooses and fires the probes and returns a verdict (detected / not_detected / inconclusive) " +
		"with per-probe evidence. GET-query based; for POST-only inputs use http_request. " +
		"Optional headers (e.g. a session Cookie from http_request) are sent on every probe. " +
		"Rate-limited in code."
}

func (WebCheck) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url":   map[string]any{"type": "string", "description": "Full URL of the page/form containing the input (scheme optional, defaults to http)"},
			"param": map[string]any{"type": "string", "description": "Name of the input parameter to test (the query parameter, or the file field name for class=upload)"},
			"class": map[string]any{"type": "string", "description": "Bug class to validate",
				"enum": []any{"sqli", "lfi", "rfi", "cmdi", "xss", "upload", "idor"}},
			"headers": map[string]any{"type": "object", "description": "Optional extra request headers (e.g. a session Cookie); sent on every probe",
				"additionalProperties": map[string]any{"type": "string"}},
		},
		"required": []any{"url", "param", "class"},
	}
}

func (WebCheck) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	const name = "web_check"
	u := strArg(args, "url")
	param := strArg(args, "param")
	cls := strings.ToLower(strArg(args, "class"))
	if u == "" || param == "" || cls == "" {
		return core.Result{Tool: name, Allowed: false, Reason: "url, param and class are all required"}
	}
	if !webcheckClasses[cls] {
		return core.Result{Tool: name, Target: u, Allowed: false,
			Reason: "class must be one of sqli, lfi, rfi, cmdi, xss, upload, idor"}
	}
	parsed, host, port, err := parseProbeURL(u)
	if err != nil {
		return core.Result{Tool: name, Target: u, Allowed: false, Reason: "invalid URL: " + err.Error()}
	}
	ok, reason := s.CheckTarget(ctx, host, &port)
	if !ok {
		return core.Result{Tool: name, Target: u, Allowed: false, Reason: reason}
	}
	orig := parsed.Query().Get(param)
	if orig == "" {
		orig = "1"
	}
	verdict, note, evidence := runClass(ctx, s, parsed, host, param, cls, orig, stringMapArg(args, "headers"))
	return core.Result{Tool: name, Target: u, Allowed: true,
		Payload: map[string]any{
			"class":    cls,
			"verdict":  verdict,
			"note":     note,
			"evidence": evidence,
		}}
}

// runClass fires the probes for one class and judges them.
func runClass(ctx context.Context, s *scope.Scope, base *url.URL, host, param, cls, orig string, hdrs map[string]string) (verdict, note string, evidence []string) {
	switch cls {
	case "upload":
		return runUpload(ctx, s, base, host, param, hdrs)
	case "sqli":
		return judgeSQLi(runProbes(ctx, s, base, host, param, hdrs, sqliProbes(orig)))
	case "lfi":
		return judgeLFI(runProbes(ctx, s, base, host, param, hdrs, lfiProbes()))
	case "rfi":
		return judgeRFI(runProbes(ctx, s, base, host, param, hdrs, rfiProbes()))
	case "cmdi":
		return judgeCmdi(runProbes(ctx, s, base, host, param, hdrs, cmdiProbes(orig)))
	case "xss":
		nonce := nonce()
		return judgeXSS(runProbes(ctx, s, base, host, param, hdrs, xssProbes(nonce)))
	case "idor":
		return judgeIDOR(runProbes(ctx, s, base, host, param, hdrs, idorProbes(orig)))
	}
	return "inconclusive", "unknown class", nil
}

// runProbes fires each spec as a GET with the query value of the parameter
// replaced, rate-limited per host.
func runProbes(ctx context.Context, s *scope.Scope, base *url.URL, host, param string, hdrs map[string]string, specs []probeSpec) []probeOutcome {
	out := make([]probeOutcome, 0, len(specs))
	for _, spec := range specs {
		u := *base
		q := u.Query()
		q.Set(param, spec.Value)
		u.RawQuery = q.Encode()
		out = append(out, doGet(ctx, s, host, spec.Name, u.String(), hdrs))
	}
	return out
}

// doGet performs one rate-limited GET and returns the observed outcome.
func doGet(ctx context.Context, s *scope.Scope, host, name, target string, hdrs map[string]string) probeOutcome {
	if err := webLimiter.Wait(ctx, host); err != nil {
		return probeOutcome{Name: name, Err: "rate limit: " + err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return probeOutcome{Name: name, Err: err.Error()}
	}
	req.Header.Set("User-Agent", "mole-web")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: webcheckTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return probeOutcome{Name: name, Err: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, webcheckCap))
	return probeOutcome{Name: name, Status: resp.StatusCode, Body: string(body)}
}

// nonce returns a random 16-hex-character string for unique markers.
func nonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "mole0000"
	}
	return hex.EncodeToString(b)
}

// evidenceLines renders one line per probe (plus a snippet where a probe hit
// something notable, supplied per class).
func evidenceLines(ps []probeOutcome, snippets ...string) []string {
	lines := make([]string, 0, len(ps)+len(snippets))
	for _, p := range ps {
		if p.Err != "" {
			lines = append(lines, fmt.Sprintf("%s: request failed (%s)", p.Name, p.Err))
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: status=%d len=%d", p.Name, p.Status, len(p.Body)))
	}
	lines = append(lines, snippets...)
	return lines
}

// similar reports whether two bodies are close enough in size to be the same
// page state (the heuristic behind boolean-diff detection).
func similar(a, b string) bool {
	la, lb := len(a), len(b)
	min := la
	if lb < min {
		min = lb
	}
	allowed := maxInt(32, int(float64(min)*0.2))
	d := la - lb
	if d < 0 {
		d = -d
	}
	return d <= allowed
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// firstSig returns the first signature present in body, or "".
func firstSig(body string, sigs []string) string {
	for _, sig := range sigs {
		if strings.Contains(body, sig) {
			return sig
		}
	}
	return ""
}

// snippet truncates a body to a short evidence excerpt.
func snippet(body, sig string) string {
	if sig == "" {
		if len(body) > 120 {
			return "body: " + body[:120]
		}
		return "body: " + body
	}
	i := strings.Index(body, sig)
	lo := i - 40
	if lo < 0 {
		lo = 0
	}
	hi := i + len(sig) + 80
	if hi > len(body) {
		hi = len(body)
	}
	return fmt.Sprintf("match (%q): …%s…", sig, body[lo:hi])
}

// ---- SQLi ---------------------------------------------------------------

func sqliProbes(orig string) []probeSpec {
	return []probeSpec{
		{"baseline", orig},
		{"AND 1=1", orig + " AND 1=1"},
		{"AND 1=2", orig + " AND 1=2"},
		{"quote", orig + "'"},
		{"OR", orig + "' OR '1'='1"},
	}
}

var sqliErrorSigs = []string{
	"You have an error in your SQL syntax",
	"Warning: mysql_",
	"Warning: mysqli_",
	"SQLSTATE[",
	"ORA-",
	"SQLite3::",
	"unterminated quoted string",
	"PostgreSQL: ERROR",
	"supplied argument is not a valid MySQL result",
}

// judgeSQLi: error-based (signature on the quote probe) first, then
// boolean blind (baseline == AND 1=1 != AND 1=2). No stacked queries.
func judgeSQLi(ps []probeOutcome) (string, string, []string) {
	for _, i := range []int{3, 4} {
		if sig := firstSig(ps[i].Body, sqliErrorSigs); sig != "" {
			return "detected", "SQL error signature on the " + ps[i].Name + " probe",
				evidenceLines(ps, snippet(ps[i].Body, sig))
		}
	}
	if ps[0].Err == "" && ps[1].Err == "" && ps[2].Err == "" {
		if similar(ps[0].Body, ps[1].Body) && !similar(ps[1].Body, ps[2].Body) {
			return "detected", "boolean-based: AND 1=1 matches the baseline, AND 1=2 changes the response",
				evidenceLines(ps)
		}
	}
	for _, p := range ps {
		if p.Err != "" {
			return "inconclusive", "probe requests failed", evidenceLines(ps)
		}
	}
	return "not_detected", "no boolean diff and no SQL error signature", evidenceLines(ps)
}

// ---- LFI ----------------------------------------------------------------

func lfiProbes() []probeSpec {
	return []probeSpec{
		{"baseline", "1"},
		{"traversal", "../../../../../../../../etc/passwd"},
		{"encoded", "..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"},
		{"absolute", "/etc/passwd"},
	}
}

func hasPasswd(body string) bool {
	return strings.Contains(body, "root:") && strings.Contains(body, "/bin/")
}

// judgeLFI: any traversal variant returning /etc/passwd content is detected.
func judgeLFI(ps []probeOutcome) (string, string, []string) {
	for _, p := range ps[1:] {
		if p.Err == "" && hasPasswd(p.Body) {
			return "detected", "response to the " + p.Name + " probe contains /etc/passwd content",
				evidenceLines(ps, snippet(p.Body, "root:"))
		}
	}
	blocked := true
	for _, p := range ps[1:] {
		if p.Err == "" && p.Status == http.StatusOK && len(p.Body) > 0 {
			blocked = false
		}
	}
	if blocked {
		return "not_detected", "traversal probes were blocked (no content returned)", evidenceLines(ps)
	}
	return "inconclusive", "no /etc/passwd content observed; inclusion may exist via a different path", evidenceLines(ps)
}

// ---- RFI ----------------------------------------------------------------

func rfiProbes() []probeSpec {
	return []probeSpec{
		{"baseline", "1"},
		{"unreachable", "http://rfi-probe.invalid/x.php"},
		{"file", "file:///etc/passwd"},
	}
}

var rfiSigs = []string{
	"failed to open stream",
	"Warning: include",
	"include(",
	"allow_url_include",
}

// judgeRFI: an include of the unreachable reference changes the response
// (with an include-failure signature) or the file:// probe leaks /etc/passwd.
// Without an out-of-band callback, absence of a visible difference is
// inconclusive, not negative.
func judgeRFI(ps []probeOutcome) (string, string, []string) {
	if p := ps[2]; p.Err == "" && hasPasswd(p.Body) {
		return "detected", "response to the file:// probe contains /etc/passwd content",
			evidenceLines(ps, snippet(p.Body, "root:"))
	}
	p := ps[1]
	if p.Err == "" && ps[0].Err == "" {
		sig := firstSig(p.Body, rfiSigs)
		if sig != "" {
			return "detected", "include-failure signature when referencing an unreachable remote file",
				evidenceLines(ps, snippet(p.Body, sig))
		}
		if p.Status != ps[0].Status || !similar(p.Body, ps[0].Body) {
			return "inconclusive", "the unreachable-reference probe changed the response, but no include signature is visible",
				evidenceLines(ps)
		}
	}
	return "inconclusive", "no observable difference from remote references; RFI confirmation needs an out-of-band callback",
		evidenceLines(ps)
}

// ---- Command injection ---------------------------------------------------

func cmdiProbes(orig string) []probeSpec {
	return []probeSpec{
		{"baseline", orig},
		{"semicolon", orig + ";id"},
		{"pipe", orig + "|id"},
		{"subshell", orig + "$(id)"},
	}
}

var uidRe = regexp.MustCompile(`uid=[0-9]+(\([a-zA-Z0-9._-]+\))?[ ]?gid=`)

// judgeCmdi: any probe whose response carries the id(1) output (uid=… gid=…)
// is a command-execution confirmation.
func judgeCmdi(ps []probeOutcome) (string, string, []string) {
	for _, p := range ps[1:] {
		if loc := uidRe.FindString(p.Body); loc != "" {
			return "detected", "the " + p.Name + " probe returned id(1) output",
				evidenceLines(ps, "match: …"+loc+"…")
		}
	}
	for _, p := range ps {
		if p.Err != "" {
			return "inconclusive", "probe requests failed", evidenceLines(ps)
		}
	}
	return "not_detected", "no command output observed in any probe", evidenceLines(ps)
}

// ---- XSS -----------------------------------------------------------------

func xssProbes(nonce string) []probeSpec {
	return []probeSpec{
		{"baseline", "1"},
		{"marker", "molexss-" + nonce},
		{"tag", "<svg/onload=alert(1)>"},
	}
}

var rawXSSTag = "<svg/onload=alert(1)>"

// judgeXSS: raw (unescaped) reflection of the HTML tag is a reflected XSS
// context; a reflected-but-escaped value is inconclusive (attribute/DOM
// contexts need manual inspection); no reflection at all is negative.
// DOM-based XSS is out of scope (no JS execution).
func judgeXSS(ps []probeOutcome) (string, string, []string) {
	if strings.Contains(ps[2].Body, rawXSSTag) {
		return "detected", "HTML tag reflected unescaped (reflected XSS context)",
			evidenceLines(ps, snippet(ps[2].Body, rawXSSTag))
	}
	if strings.Contains(ps[1].Body, "molexss-") {
		return "inconclusive", "input value is reflected, but the HTML context appears escaped — inspect surrounding markup for attribute/DOM context",
			evidenceLines(ps)
	}
	return "not_detected", "input value not reflected in the response", evidenceLines(ps)
}

// ---- Upload ---------------------------------------------------------------

// uploadContent is the fixed harmless file written by the upload probe.
const uploadContent = "MOLE harmless validation upload (text file, safe to delete)."

// runUpload POSTs the fixed text file to the named file field, then tries to
// fetch it back via any URL the response gives that contains the filename.
func runUpload(ctx context.Context, s *scope.Scope, base *url.URL, host, field string, hdrs map[string]string) (string, string, []string) {
	name := "mole-upload-" + nonce() + ".txt"
	var buf bytes.Buffer
	w := newMultipart(&buf, field, name, uploadContent)
	if err := webLimiter.Wait(ctx, host); err != nil {
		return "inconclusive", "rate limit: " + err.Error(), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), &buf)
	if err != nil {
		return "inconclusive", "building request: " + err.Error(), nil
	}
	req.Header.Set("User-Agent", "mole-web")
	req.Header.Set("Content-Type", w.FormDataContentType())
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: webcheckTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "inconclusive", "upload request failed: " + err.Error(), nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, webcheckCap))
	resp.Body.Close()
	post := probeOutcome{Name: "upload POST", Status: resp.StatusCode, Body: string(body)}

	stored := findStoredURL(base, string(body), name)
	if stored != "" {
		if err := webLimiter.Wait(ctx, host); err != nil {
			return "inconclusive", "rate limit: " + err.Error(), []string{fmt.Sprintf("upload POST: status=%d len=%d", post.Status, len(post.Body))}
		}
		freq, ferr := http.NewRequestWithContext(ctx, http.MethodGet, stored, nil)
		if ferr == nil {
			freq.Header.Set("User-Agent", "mole-web")
			for k, v := range hdrs {
				freq.Header.Set(k, v)
			}
			fresp, ferr := client.Do(freq)
			if ferr == nil {
				fbody, _ := io.ReadAll(io.LimitReader(fresp.Body, webcheckCap))
				fresp.Body.Close()
				fetch := probeOutcome{Name: "fetch-back " + stored, Status: fresp.StatusCode, Body: string(fbody)}
				if strings.Contains(fetch.Body, uploadContent) {
					return "detected", "uploaded file is retrievable with identical content",
						evidenceLines([]probeOutcome{post, fetch})
				}
				return "inconclusive", "upload accepted and a stored URL was found, but its content differs",
					evidenceLines([]probeOutcome{post, fetch})
			}
		}
	}
	if resp.StatusCode == http.StatusOK {
		return "inconclusive", "server accepted the upload, but the stored location is not observable from the response — locate the stored file and verify with http_probe",
			[]string{fmt.Sprintf("upload POST: status=%d len=%d", post.Status, len(post.Body))}
	}
	return "not_detected", "upload was rejected (status " + strconv.Itoa(resp.StatusCode) + ")",
		[]string{fmt.Sprintf("upload POST: status=%d", post.Status)}
}

// newMultipart writes a single-file multipart form into buf.
func newMultipart(buf *bytes.Buffer, field, filename, content string) *multipart.Writer {
	w := multipart.NewWriter(buf)
	fw, _ := w.CreateFormFile(field, filename)
	fw.Write([]byte(content))
	w.Close()
	return w
}

// findStoredURL looks in the upload response for a reference to the stored
// file (href attribute or bare path containing the filename) and returns an
// absolute URL for it, scoped to the same base.
func findStoredURL(base *url.URL, body, filename string) string {
	for _, m := range storedURLRe.FindAllStringSubmatch(body, -1) {
		cand := strings.TrimSpace(m[1])
		if cand == "" || !strings.Contains(cand, filename) {
			continue
		}
		if u, err := url.Parse(cand); err == nil {
			if u.IsAbs() {
				return u.String()
			}
			if strings.HasPrefix(cand, "/") {
				abs := *base
				abs.Path = u.Path
				abs.RawQuery = u.RawQuery
				return abs.String()
			}
		}
	}
	return ""
}

var storedURLRe = regexp.MustCompile(`href="([^"]+)"`)

// ---- IDOR -----------------------------------------------------------------

func idorProbes(orig string) []probeSpec {
	next := orig + "2"
	if n, err := strconv.Atoi(orig); err == nil {
		next = strconv.Itoa(n + 1)
	}
	seen := map[string]bool{}
	var out []probeSpec
	add := func(name, value string) {
		if !seen[value] {
			seen[value] = true
			out = append(out, probeSpec{Name: name, Value: value})
		}
	}
	add("baseline", orig)
	add("next", next)
	add("first", "1")
	add("high", "999999")
	return out
}

// judgeIDOR: unauthenticated observation only. Different object content for
// different accessible IDs means access control is not enforced where
// observable; denial of every ID other than the original (or of all of them)
// is negative; identical content across accessible IDs is inconclusive.
func judgeIDOR(ps []probeOutcome) (string, string, []string) {
	for _, p := range ps {
		if p.Err != "" {
			return "inconclusive", "probe requests failed", evidenceLines(ps)
		}
	}
	var ok []probeOutcome
	for _, p := range ps {
		if p.Status == http.StatusOK && len(p.Body) > 0 {
			ok = append(ok, p)
		}
	}
	if len(ok) >= 2 {
		for i := range ok {
			for j := i + 1; j < len(ok); j++ {
				if strings.TrimSpace(ok[i].Body) != strings.TrimSpace(ok[j].Body) {
					return "detected", "different object content returned for different object IDs (unauthenticated observation)",
						evidenceLines(ps)
				}
			}
		}
		return "inconclusive", "identical response for all accessible probed IDs — the parameter may not select objects",
			evidenceLines(ps)
	}
	return "not_detected", "access denied for every probed object ID other than the original (unauthenticated observation)",
		evidenceLines(ps)
}
