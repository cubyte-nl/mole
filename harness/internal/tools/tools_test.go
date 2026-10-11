package tools

import (
	"context"
	"encoding/json"
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

	"mole/internal/scope"
)

var testCtx = context.Background()

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
	reg := NewRegistry(false)
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
	specs := NewRegistry(false).Specs()
	names := map[string]bool{}
	for _, sp := range specs {
		names[sp.Function.Name] = true
	}
	for _, want := range []string{"dns_lookup", "nmap", "http_probe", "tls_probe", "tcp_probe", "security_headers", "subdomains"} {
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

	// Registry gating: a reconnaissance engagement cannot reach nuclei at all.
	if res := NewRegistry(false).Run(testCtx, s, "nuclei", `{"url":"http://127.0.0.1/"}`); res.Allowed {
		t.Error("nuclei reachable in a reconnaissance registry")
	}
	reconNames := map[string]bool{}
	for _, sp := range NewRegistry(false).Specs() {
		reconNames[sp.Function.Name] = true
	}
	if reconNames["nuclei"] {
		t.Error("nuclei spec exposed in a reconnaissance registry")
	}

	// Active engagement: the gate passes and the run is allowed, degrading
	// gracefully when the binary is missing (same pattern as nmap).
	res := NewRegistry(true).Run(testCtx, s, "nuclei", `{"url":"http://127.0.0.1/"}`)
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
