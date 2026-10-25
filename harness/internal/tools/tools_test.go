package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/ledger"
	"mole/internal/scope"
)

var testCtx = context.Background()

// newLedger opens a throwaway findings ledger for a test.
func newLedger(t *testing.T) *ledger.Ledger {
	t.Helper()
	l, err := ledger.New(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	return l
}

// registered reports whether a tool of the given name is exposed by the
// registry, via its public Specs (the core registry's map is unexported).
func registered(reg *core.Registry[*scope.Scope], name string) bool {
	for _, sp := range reg.Specs() {
		if sp.Function.Name == name {
			return true
		}
	}
	return false
}

func testScope(inScope ...string) *scope.Scope {
	return &scope.Scope{
		Name:    "unit-test",
		InScope: inScope,
		Auth:    scope.Authorization{Basis: scope.BasisCTFLab, Operator: "t", Date: "2026-10-07", Confirmed: true},
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestTLSProbe(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	s := testScope("127.0.0.1")
	res := TLSProbe{}.Run(testCtx, s, map[string]any{"host": "127.0.0.1", "port": port})
	if !res.Allowed {
		t.Fatalf("tls probe denied: %s", res.Reason)
	}
	p, ok := res.Payload.(map[string]any)
	if !ok {
		t.Fatalf("payload type %T", res.Payload)
	}
	leaf := srv.Certificate()
	if p["common_name"] != leaf.Subject.CommonName {
		t.Errorf("common_name = %v, want %v", p["common_name"], leaf.Subject.CommonName)
	}
	sans, _ := p["san_dns"].([]string)
	for _, want := range leaf.DNSNames {
		if !contains(sans, want) {
			t.Errorf("san_dns %v missing %s", sans, want)
		}
	}
	if p["expired"] != false {
		t.Errorf("expired = %v, want false", p["expired"])
	}
	if p["chain_length"] != 1 {
		t.Errorf("chain_length = %v, want 1", p["chain_length"])
	}
	ver, _ := p["tls_version"].(string)
	if !strings.HasPrefix(ver, "TLS 1.") {
		t.Errorf("tls_version = %q, want TLS 1.x", ver)
	}

	// Gate: an out-of-scope host must be denied before the handshake.
	if res := (TLSProbe{}.Run(testCtx, s, map[string]any{"host": "definitely-not-a-host.invalid"})); res.Allowed {
		t.Error("out-of-scope host was allowed")
	}
}

func TestTCPProbe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	openPort := l.Addr().(*net.TCPAddr).Port

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := l2.Addr().(*net.TCPAddr).Port
	l2.Close()

	s := testScope("127.0.0.1")
	res := TCPProbe{}.Run(testCtx, s, map[string]any{
		"host":  "127.0.0.1",
		"ports": []any{float64(openPort), float64(closedPort)},
	})
	if !res.Allowed {
		t.Fatalf("tcp probe denied: %s", res.Reason)
	}
	ports := res.Payload.(map[string]any)["ports"].([]map[string]any)
	if ports[0]["open"] != true {
		t.Errorf("listening port %d: open = %v", openPort, ports[0]["open"])
	}
	if ports[1]["open"] != false {
		t.Errorf("closed port %d: open = %v", closedPort, ports[1]["open"])
	}

	// The gate is applied per port: a port outside the allowed list is denied,
	// not checked.
	s2 := testScope("127.0.0.1")
	s2.Ports = []int{openPort}
	res2 := TCPProbe{}.Run(testCtx, s2, map[string]any{
		"host":  "127.0.0.1",
		"ports": []any{float64(openPort), float64(closedPort)},
	})
	ports2 := res2.Payload.(map[string]any)["ports"].([]map[string]any)
	if ports2[0]["open"] != true {
		t.Errorf("allowed port not reported open: %v", ports2[0])
	}
	if _, denied := ports2[1]["gate"]; !denied {
		t.Errorf("port outside allowed list not gate-denied: %v", ports2[1])
	}

	// Registry path: JSON arguments are parsed.
	reg := NewRegistry(false, newLedger(t), newKB())
	if res := reg.Run(testCtx, s, "tcp_probe", `{"host":"127.0.0.1","ports":[`+strconv.Itoa(openPort)+`]}`); !res.Allowed {
		t.Errorf("registry tcp_probe denied: %s", res.Reason)
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Add("Set-Cookie", "session=abc123")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := newProbeClient
	newProbeClient = func() *http.Client { return srv.Client() }
	defer func() { newProbeClient = old }()

	s := testScope("127.0.0.1")
	res := SecurityHeaders{}.Run(testCtx, s, map[string]any{"url": srv.URL + "/"})
	if !res.Allowed {
		t.Fatalf("security_headers denied: %s", res.Reason)
	}
	p := res.Payload.(map[string]any)
	verdicts := map[string]string{}
	for _, c := range p["checks"].([]map[string]any) {
		verdicts[c["header"].(string)] = c["verdict"].(string)
	}
	want := map[string]string{
		"Strict-Transport-Security": "ok",
		"Content-Security-Policy":   "ok",
		"X-Frame-Options":           "missing",
		"X-Content-Type-Options":    "ok",
		"Referrer-Policy":           "ok",
		"Permissions-Policy":        "missing",
		"Set-Cookie":                "weak",
	}
	for h, v := range want {
		if got := verdicts[h]; got != v {
			t.Errorf("%s verdict = %q, want %q", h, got, v)
		}
	}

	// HSTS over plaintext HTTP is ignored by browsers: a weak finding.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	}))
	defer plain.Close()
	res2 := SecurityHeaders{}.Run(testCtx, s, map[string]any{"url": plain.URL + "/"})
	if !res2.Allowed {
		t.Fatalf("plaintext security_headers denied: %s", res2.Reason)
	}
	for _, c := range res2.Payload.(map[string]any)["checks"].([]map[string]any) {
		if c["header"] == "Strict-Transport-Security" && c["verdict"] != "weak" {
			t.Errorf("plaintext HSTS verdict = %v, want weak", c["verdict"])
		}
	}
}

func TestSubdomains(t *testing.T) {
	// Target a bare IP, not localhost: some resolvers (e.g. systemd-resolved
	// per RFC 6761) wildcard *.localhost to 127.0.0.1, which would trip the
	// wildcard filter and drop the apex. 127.0.0.1 resolves to itself with
	// no DNS at all, so the probe is deterministic and offline.
	s := testScope("127.0.0.1")

	// Built-in list: only the apex itself resolves (www.127.0.0.1,
	// mail.127.0.0.1, ... do not), so exactly one name is reported.
	res := Subdomains{}.Run(testCtx, s, map[string]any{"domain": "127.0.0.1"})
	if !res.Allowed {
		t.Fatalf("subdomains denied: %s", res.Reason)
	}
	p := res.Payload.(map[string]any)
	if p["count"] != 1 {
		t.Fatalf("count = %v, want 1 (names: %v)", p["count"], p["names"])
	}
	names := p["names"].([]string)
	if len(names) != 1 || names[0] != "127.0.0.1" {
		t.Fatalf("names = %v, want [127.0.0.1]", names)
	}
	if p["wildcard"] != false {
		t.Errorf("wildcard = %v, want false", p["wildcard"])
	}
	addrs := p["addresses"].(map[string][]string)
	ipAddrs, _ := addrs["127.0.0.1"]
	if !contains(ipAddrs, "127.0.0.1") {
		t.Errorf("apex addresses = %v, want 127.0.0.1", ipAddrs)
	}

	// Wordlist file: comments and *. prefixes are handled, labels and full
	// names are deduped, and only names that resolve are reported.
	path := filepath.Join(t.TempDir(), "subs.txt")
	wl := "# a comment\n127.0.0.1\n*.127.0.0.1\nnope-mzn-1234.127.0.0.1\n"
	if err := os.WriteFile(path, []byte(wl), 0o644); err != nil {
		t.Fatalf("writing wordlist: %v", err)
	}
	res2 := Subdomains{}.Run(testCtx, s, map[string]any{"domain": "127.0.0.1", "wordlist": path})
	if !res2.Allowed {
		t.Fatalf("subdomains with wordlist denied: %s", res2.Reason)
	}
	p2 := res2.Payload.(map[string]any)
	if p2["count"] != 1 {
		t.Fatalf("wordlist count = %v, want 1 (names: %v)", p2["count"], p2["names"])
	}
	names2 := p2["names"].([]string)
	if len(names2) != 1 || names2[0] != "127.0.0.1" {
		t.Fatalf("wordlist names = %v, want [127.0.0.1]", names2)
	}
	if p2["probed"] != 2 {
		t.Errorf("probed = %v, want 2 (apex + the one non-resolving label)", p2["probed"])
	}

	// Gate: a domain outside the scope must be denied.
	if res := (Subdomains{}.Run(testCtx, s, map[string]any{"domain": "example.org"})); res.Allowed {
		t.Error("out-of-scope domain was allowed")
	}
}

func TestRegistrySpecsIncludeNewTools(t *testing.T) {
	specs := NewRegistry(false, newLedger(t), newKB()).Specs()
	names := map[string]bool{}
	for _, sp := range specs {
		names[sp.Function.Name] = true
	}
	for _, want := range []string{"dns_lookup", "nmap", "http_probe", "tls_probe", "tcp_probe", "security_headers", "subdomains", "knowledge_search", "shell", "record_finding", "update_finding"} {
		if !names[want] {
			t.Errorf("registry missing tool %q", want)
		}
	}
	raw, _ := json.Marshal(specs)
	if !strings.Contains(string(raw), "tls_probe") {
		t.Error("specs do not render tls_probe")
	}
}

func TestNuclei(t *testing.T) {
	s := testScope("127.0.0.1")

	// Missing url is denied before anything else.
	if res := (Nuclei{}).Run(testCtx, s, map[string]any{}); res.Allowed {
		t.Error("missing url was allowed")
	}

	// Out-of-scope target is gate-denied (before the binary is looked up).
	if res := (Nuclei{}).Run(testCtx, s, map[string]any{"url": "http://example.org/"}); res.Allowed {
		t.Errorf("out-of-scope URL was allowed: %s", res.Reason)
	}

	// A typo in severity is denied up front, not wasted on a full run.
	if res := (Nuclei{}).Run(testCtx, s, map[string]any{"url": "http://127.0.0.1/", "severity": "severe"}); res.Allowed {
		t.Errorf("invalid severity was allowed: %s", res.Reason)
	}

	// Registry gating: a reconnaissance engagement cannot reach nuclei at all.
	if res := NewRegistry(false, newLedger(t), newKB()).Run(testCtx, s, "nuclei", `{"url":"http://127.0.0.1/"}`); res.Allowed {
		t.Error("nuclei reachable in a reconnaissance registry")
	}
	reconNames := map[string]bool{}
	for _, sp := range NewRegistry(false, newLedger(t), newKB()).Specs() {
		reconNames[sp.Function.Name] = true
	}
	if reconNames["nuclei"] {
		t.Error("nuclei spec exposed in a reconnaissance registry")
	}

	// Active engagement: the gate passes and the run is allowed, degrading
	// gracefully when the binary is missing (same pattern as nmap).
	res := NewRegistry(true, newLedger(t), newKB()).Run(testCtx, s, "nuclei", `{"url":"http://127.0.0.1/"}`)
	if !res.Allowed {
		t.Fatalf("in-scope nuclei run denied: %s", res.Reason)
	}
	if res.Target != "127.0.0.1" {
		t.Errorf("target = %q, want 127.0.0.1", res.Target)
	}
	if _, err := exec.LookPath("nuclei"); err != nil {
		if !strings.Contains(res.Reason, "not installed") {
			t.Errorf("expected graceful-degradation reason, got %q", res.Reason)
		}
	}
}

func TestFfuf(t *testing.T) {
	s := testScope("127.0.0.1")

	// Missing url is denied before anything else.
	if res := (Ffuf{}).Run(testCtx, s, map[string]any{}); res.Allowed {
		t.Error("missing url was allowed")
	}

	// Out-of-scope target is gate-denied (before the binary is looked up).
	if res := (Ffuf{}).Run(testCtx, s, map[string]any{"url": "http://example.org/"}); res.Allowed {
		t.Errorf("out-of-scope URL was allowed: %s", res.Reason)
	}

	// Registry gating: a reconnaissance engagement cannot reach ffuf at all,
	// while knowledge_search (a local, non-mutating tool) is always exposed.
	if res := NewRegistry(false, newLedger(t), newKB()).Run(testCtx, s, "ffuf", `{"url":"http://127.0.0.1/"}`); res.Allowed {
		t.Error("ffuf reachable in a reconnaissance registry")
	}
	reconNames := map[string]bool{}
	for _, sp := range NewRegistry(false, newLedger(t), newKB()).Specs() {
		reconNames[sp.Function.Name] = true
	}
	if reconNames["ffuf"] {
		t.Error("ffuf spec exposed in a reconnaissance registry")
	}
	if !reconNames["knowledge_search"] {
		t.Error("knowledge_search missing from a reconnaissance registry")
	}

	// Active engagement: the gate passes and the run is allowed, degrading
	// gracefully when the binary is missing (same pattern as nuclei).
	res := NewRegistry(true, newLedger(t), newKB()).Run(testCtx, s, "ffuf", `{"url":"http://127.0.0.1/"}`)
	if !res.Allowed {
		t.Fatalf("in-scope ffuf run denied: %s", res.Reason)
	}
	if res.Target != "127.0.0.1" {
		t.Errorf("target = %q, want 127.0.0.1", res.Target)
	}
	if _, err := exec.LookPath("ffuf"); err != nil {
		if !strings.Contains(res.Reason, "not installed") {
			t.Errorf("expected graceful-degradation reason, got %q", res.Reason)
		}
	}
}

func TestExpandFfufPaths(t *testing.T) {
	// Extensionless entries are probed as-is and with each extension; entries
	// that already contain a dot are full filenames and are not expanded.
	got := expandFfufPaths([]string{"admin", ".git", "wp-login.php"}, []string{"php", "asp"})
	want := []string{"admin", "admin.php", "admin.asp", ".git", "wp-login.php"}
	if len(got) != len(want) || !equalStrings(got, want) {
		t.Errorf("expanded = %v, want %v", got, want)
	}

	// Duplicates collapse.
	got = expandFfufPaths([]string{"admin", "admin"}, []string{"php"})
	if !equalStrings(got, []string{"admin", "admin.php"}) {
		t.Errorf("dupes not collapsed: %v", got)
	}

	// No extensions: entries are probed as-is.
	got = expandFfufPaths([]string{"a", "b"}, nil)
	if !equalStrings(got, []string{"a", "b"}) {
		t.Errorf("no-extension expansion = %v", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTrimFfufOutput(t *testing.T) {
	raw := `{"results":[
		{"input":{"FFUF":"admin.php"},"status":403,"length":152},
		{"input":{"FFUF":".git"},"status":200,"length":100}
	]}`
	out := trimFfufOutput(raw)
	if !strings.Contains(out, "[403] /admin.php (length=152)") ||
		!strings.Contains(out, "[200] /.git (length=100)") {
		t.Errorf("hit lines malformed:\n%s", out)
	}

	// Non-JSON output (errors, empty runs) passes through trimmed.
	if got := trimFfufOutput("  ffuf error: something\n"); got != "ffuf error: something" {
		t.Errorf("non-JSON passthrough = %q", got)
	}

	// Hits beyond maxFfufHits are capped, with a note about the dropped ones.
	var b strings.Builder
	b.WriteString(`{"results":[`)
	for i := 0; i < maxFfufHits+3; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"input":{"FFUF":"p%d"},"status":200,"length":1}`, i)
	}
	b.WriteString("]}")
	capped := trimFfufOutput(b.String())
	if !strings.Contains(capped, "3 additional hit(s) trimmed") {
		t.Errorf("cap note missing:\n%s", capped)
	}
	if lines := strings.Split(capped, "\n"); len(lines) != maxFfufHits+1 { // hits + cap note
		t.Errorf("expected %d lines, got %d", maxFfufHits+1, len(lines))
	}
}

func TestTrimNucleiOutput(t *testing.T) {
	finding := `{"template-id":"tls-version","info":{"severity":"info"},"matched-at":"127.0.0.1:443","request":"GET / HTTP/1.1...","response":"HTTP/1.1 200 OK\r\n<huge body>"}`
	warning := "WARNING: sonic/ast fallback"
	out := trimNucleiOutput(warning + "\n" + finding + "\n")

	if !strings.Contains(out, "WARNING: sonic/ast fallback") {
		t.Error("non-JSON banner line should pass through untouched")
	}
	if strings.Contains(out, "request") || strings.Contains(out, "response") || strings.Contains(out, "huge body") {
		t.Errorf("request/response bodies should be dropped:\n%s", out)
	}
	if !strings.Contains(out, "tls-version") || !strings.Contains(out, "matched-at") || !strings.Contains(out, "severity") {
		t.Errorf("finding identity fields should be kept:\n%s", out)
	}
}

func TestTrimNucleiOutputOrderingAndCap(t *testing.T) {
	mk := func(id, sev string) string {
		return fmt.Sprintf(`{"template-id":%q,"info":{"severity":%q},"matched-at":"127.0.0.1:443","response":"x"}`, id, sev)
	}
	// A medium finding listed before an info one, and a critical one last:
	// the output must be re-ordered most-severe first.
	out := trimNucleiOutput(mk("medium-one", "medium") + "\n" + mk("info-one", "info") + "\n" + mk("critical-one", "critical") + "\n")
	if strings.Index(out, "critical-one") > strings.Index(out, "medium-one") ||
		strings.Index(out, "medium-one") > strings.Index(out, "info-one") {
		t.Errorf("findings should be ordered most-severe first:\n%s", out)
	}

	// maxFindings+1 findings: capped at maxFindings, with a note about the
	// dropped one. The dropped finding is the last same-severity one (stable
	// order); earlier info findings and the critical one survive.
	var b strings.Builder
	for i := 0; i < maxFindings-1; i++ {
		fmt.Fprintf(&b, "%s\n", mk(fmt.Sprintf("info-%d", i), "info"))
	}
	fmt.Fprintf(&b, "%s\n%s\n", mk("info-49", "info"), mk("critical-final", "critical"))
	capped := trimNucleiOutput(b.String())
	if !strings.Contains(capped, "1 lower-severity finding(s) trimmed") {
		t.Errorf("cap note missing:\n%s", capped)
	}
	if !strings.Contains(capped, "info-0") {
		t.Errorf("earlier same-severity findings should survive the cap:\n%s", capped)
	}
	if strings.Contains(capped, "info-49") {
		t.Errorf("the dropped finding should be the last same-severity one:\n%s", capped)
	}
	if !strings.Contains(capped, "critical-final") {
		t.Errorf("the most severe finding must survive the cap:\n%s", capped)
	}
	lines := strings.Split(strings.TrimSpace(capped), "\n")
	if len(lines) != maxFindings+1 { // findings + cap note
		t.Errorf("expected %d lines, got %d", maxFindings+1, len(lines))
	}
}

func TestTrimNucleiOutputDedupe(t *testing.T) {
	mk := func(matcher string) string {
		return fmt.Sprintf(`{"template-id":"http-missing-security-headers","info":{"severity":"info"},"matched-at":"http://127.0.0.1/","matcher-name":%q,"request":"r","response":"resp"}`, matcher)
	}
	// One template can match once per matcher on the same target (real
	// nuclei emits ~8 lines for missing-security-headers); they collapse to
	// one line with the matcher names aggregated.
	out := trimNucleiOutput(mk("strict-transport-security") + "\n" + mk("content-security-policy") + "\n" + mk("strict-transport-security") + "\n")
	if got := strings.Count(out, "http-missing-security-headers"); got != 1 {
		t.Errorf("expected 1 deduplicated finding line, got %d:\n%s", got, out)
	}
	for _, m := range []string{"strict-transport-security", "content-security-policy"} {
		if !strings.Contains(out, m) {
			t.Errorf("matcher name %q should survive aggregation:\n%s", m, out)
		}
	}
	if strings.Contains(out, "resp") {
		t.Errorf("response body should be trimmed:\n%s", out)
	}

	// The same template on a different target is a distinct finding.
	other := `{"template-id":"http-missing-security-headers","info":{"severity":"info"},"matched-at":"http://other/"}`
	out = trimNucleiOutput(mk("content-security-policy") + "\n" + other + "\n")
	if got := strings.Count(out, "http-missing-security-headers"); got != 2 {
		t.Errorf("same template on two targets should stay two lines:\n%s", out)
	}
}
