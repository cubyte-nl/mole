package tools

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mole/internal/scope"
)

// startVulnServer serves the vulnerable endpoints used by the web_check
// tests: each handler emulates one bug class in the minimal observable form
// (SQL error page, /etc/passwd content, id(1) output, raw reflection, ...).
func startVulnServer(t *testing.T) (*httptest.Server, map[string]string) {
	t.Helper()
	uploads := map[string]string{}
	mux := http.NewServeMux()

	rows := func(n int) string {
		var b strings.Builder
		b.WriteString("<html><body><table>")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "<tr><td>row %04d</td><td>some payload that pads the row out to a stable length</td></tr>", i)
		}
		b.WriteString("</table></body></html>")
		return b.String()
	}
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

	mux.HandleFunc("/sqli-error.php", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			http.Error(w, "You have an error in your SQL syntax; check the manual near '"+id+"'", http.StatusInternalServerError)
			return
		}
		if strings.Contains(id, "AND 1=2") {
			fmt.Fprint(w, rows(0))
			return
		}
		fmt.Fprint(w, rows(3))
	})
	mux.HandleFunc("/sqli-boolean.php", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "AND 1=2") {
			fmt.Fprint(w, rows(0))
			return
		}
		fmt.Fprint(w, rows(3))
	})
	mux.HandleFunc("/lfi.php", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "passwd") {
			fmt.Fprint(w, "<pre>"+passwd+"</pre>")
			return
		}
		fmt.Fprint(w, "<html><body>include page</body></html>")
	})
	mux.HandleFunc("/rfi.php", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		switch {
		case strings.HasPrefix(file, "http://"):
			fmt.Fprintf(w, "<html><body>Warning: include(%s): failed to open stream: HTTP request failed in /var/www/rfi.php on line 12</body></html>", file)
		case file == "file:///etc/passwd":
			fmt.Fprint(w, "<pre>"+passwd+"</pre>")
		default:
			fmt.Fprint(w, "<html><body>include page</body></html>")
		}
	})
	mux.HandleFunc("/cmdi.php", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		out := "Poking " + ip
		if strings.Contains(ip, ";id") || strings.Contains(ip, "|id") || strings.Contains(ip, "$(id)") {
			out += "\nuid=33(www-data) gid=33(www-data) groups=33(www-data)"
		}
		fmt.Fprint(w, "<html><body><pre>"+out+"</pre></body></html>")
	})
	mux.HandleFunc("/xss-raw.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>Search results for: %s</body></html>", r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/xss-escaped.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>Search results for: %s</body></html>", html.EscapeString(r.URL.Query().Get("q")))
	})
	mux.HandleFunc("/upload.php", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "not multipart", http.StatusBadRequest)
			return
		}
		f, hdr, err := r.FormFile("userfile")
		if err != nil {
			http.Error(w, "missing userfile", http.StatusBadRequest)
			return
		}
		data, _ := io.ReadAll(f)
		f.Close()
		uploads[hdr.Filename] = string(data)
		fmt.Fprintf(w, "<html><body>Upload complete! <a href=\"/uploads/%s\">view %s</a></body></html>", hdr.Filename, hdr.Filename)
	})
	mux.HandleFunc("/uploads/", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if data, ok := uploads[name]; ok {
			fmt.Fprint(w, data)
			return
		}
		http.Error(w, "no such file", http.StatusNotFound)
	})
	mux.HandleFunc("/upload-denied.php", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not an upload endpoint", http.StatusBadRequest)
	})
	mux.HandleFunc("/idor-open.php", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("itemid") {
		case "1":
			fmt.Fprint(w, "<html><body>Product: Alpha Widget — SKU 1001, in stock, $10.00</body></html>")
		case "2":
			fmt.Fprint(w, "<html><body>Product: Beta Gadget — SKU 2002, backordered, $20.00</body></html>")
		default:
			http.Error(w, "item not found", http.StatusNotFound)
		}
	})
	mux.HandleFunc("/idor-closed.php", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("itemid") == "1" {
			fmt.Fprint(w, "<html><body>Product: Alpha Widget — SKU 1001</body></html>")
			return
		}
		http.Error(w, "access denied", http.StatusForbidden)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, uploads
}

// expectVerdict runs web_check on the target and asserts the verdict.
func expectVerdict(t *testing.T, s *scope.Scope, target, param, cls, want string) {
	t.Helper()
	res := (WebCheck{}).Run(testCtx, s, map[string]any{"url": target, "param": param, "class": cls})
	if !res.Allowed {
		t.Fatalf("web_check(%s) denied: %s", cls, res.Reason)
	}
	pl, _ := res.Payload.(map[string]any)
	if pl == nil {
		t.Fatalf("web_check(%s) payload missing: %v", cls, res.Payload)
	}
	if got, _ := pl["verdict"].(string); got != want {
		t.Errorf("web_check(%s) verdict = %q, want %q\nnote: %v\nevidence: %v",
			cls, got, want, pl["note"], pl["evidence"])
	}
}

func TestWebCheckSQLi(t *testing.T) {
	srv, _ := startVulnServer(t)
	s := testScope("127.0.0.1")
	expectVerdict(t, s, srv.URL+"/sqli-error.php?id=1", "id", "sqli", "detected")
	expectVerdict(t, s, srv.URL+"/sqli-boolean.php?id=1", "id", "sqli", "detected")
}

func TestWebCheckSQLiClean(t *testing.T) {
	srv, _ := startVulnServer(t)
	s := testScope("127.0.0.1")
	// /xss-raw.php echoes the parameter, so AND 1=1 and AND 1=2 both render
	// the same page: no boolean diff, no error signature.
	expectVerdict(t, s, srv.URL+"/xss-raw.php?q=1", "q", "sqli", "not_detected")
}

func TestWebCheckLFI(t *testing.T) {
	srv, _ := startVulnServer(t)
	s := testScope("127.0.0.1")
	expectVerdict(t, s, srv.URL+"/lfi.php?file=home", "file", "lfi", "detected")
}

func TestWebCheckRFI(t *testing.T) {
	srv, _ := startVulnServer(t)
	s := testScope("127.0.0.1")
	expectVerdict(t, s, srv.URL+"/rfi.php?file=home", "file", "rfi", "detected")
}

func TestWebCheckCmdi(t *testing.T) {
	srv, _ := startVulnServer(t)
	s := testScope("127.0.0.1")
	expectVerdict(t, s, srv.URL+"/cmdi.php?ip=127.0.0.1", "ip", "cmdi", "detected")
}

func TestWebCheckCmdiClean(t *testing.T) {
	srv, _ := startVulnServer(t)
	s := testScope("127.0.0.1")
	// Raw reflection of the ip value, no command execution.
	expectVerdict(t, s, srv.URL+"/xss-raw.php?q=127.0.0.1", "q", "cmdi", "not_detected")
}

func TestWebCheckXSS(t *testing.T) {
	srv, _ := startVulnServer(t)
	s := testScope("127.0.0.1")
	expectVerdict(t, s, srv.URL+"/xss-raw.php?q=1", "q", "xss", "detected")
	expectVerdict(t, s, srv.URL+"/xss-escaped.php?q=1", "q", "xss", "inconclusive")
}

func TestWebCheckUpload(t *testing.T) {
	srv, uploads := startVulnServer(t)
	s := testScope("127.0.0.1")
	expectVerdict(t, s, srv.URL+"/upload.php", "userfile", "upload", "detected")
	if len(uploads) != 1 {
		t.Fatalf("server stored %d files, want 1: %v", len(uploads), uploads)
	}
	for name, data := range uploads {
		if !strings.HasPrefix(name, "mole-upload-") || !strings.HasSuffix(name, ".txt") {
			t.Errorf("stored file %q is not the fixed harmless text file", name)
		}
		if !strings.Contains(data, "harmless") {
			t.Errorf("stored file content is not the fixed harmless content: %q", data)
		}
	}
}

func TestWebCheckUploadRejected(t *testing.T) {
	srv, _ := startVulnServer(t)
	s := testScope("127.0.0.1")
	expectVerdict(t, s, srv.URL+"/upload-denied.php", "userfile", "upload", "not_detected")
}

func TestWebCheckIDOR(t *testing.T) {
	srv, _ := startVulnServer(t)
	s := testScope("127.0.0.1")
	expectVerdict(t, s, srv.URL+"/idor-open.php?itemid=1", "itemid", "idor", "detected")
	expectVerdict(t, s, srv.URL+"/idor-closed.php?itemid=1", "itemid", "idor", "not_detected")
}

func TestWebCheckScopeDenial(t *testing.T) {
	srv, _ := startVulnServer(t)
	s := testScope("127.0.0.2") // the test server is not in this scope
	res := (WebCheck{}).Run(testCtx, s, map[string]any{"url": srv.URL + "/lfi.php?page=1", "param": "page", "class": "lfi"})
	if res.Allowed {
		t.Error("out-of-scope web_check was allowed")
	}
}

func TestWebCheckArgValidation(t *testing.T) {
	s := testScope("127.0.0.1")
	for _, args := range []map[string]any{
		{"url": "http://127.0.0.1/x", "param": "id", "class": "nosuch"},
		{"url": "http://127.0.0.1/x", "param": "", "class": "sqli"},
		{"url": "", "param": "id", "class": "sqli"},
	} {
		res := (WebCheck{}).Run(testCtx, s, args)
		if res.Allowed {
			t.Errorf("web_check with args %v was allowed", args)
		}
	}
}

func TestWebCheckRegistryGating(t *testing.T) {
	if registered(NewRegistry(false, newLedger(t), newKB()), "web_check") {
		t.Error("web_check registered in a reconnaissance registry")
	}
	if registered(NewRegistry(false, newLedger(t), newKB()), "http_request") {
		t.Error("http_request registered in a reconnaissance registry")
	}
	vuln := NewRegistry(true, newLedger(t), newKB())
	if !registered(vuln, "web_check") {
		t.Error("web_check missing from a vulnerability-scanning registry")
	}
	if !registered(vuln, "http_request") {
		t.Error("http_request missing from a vulnerability-scanning registry")
	}
}

func TestHTTPRequestRoundTrip(t *testing.T) {
	var gotMethod, gotHeader, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotHeader = r.Header.Get("X-Custom")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		fmt.Fprintf(w, "echo %s", gotBody)
	}))
	defer srv.Close()
	s := testScope("127.0.0.1")
	res := (HTTPRequest{}).Run(testCtx, s, map[string]any{
		"url":     srv.URL + "/echo",
		"method":  "post",
		"headers": map[string]any{"X-Custom": "probe-1"},
		"body":    "field=1;id",
	})
	if !res.Allowed {
		t.Fatalf("http_request denied: %s", res.Reason)
	}
	pl := res.Payload.(map[string]any)
	if gotMethod != http.MethodPost {
		t.Errorf("server saw method %q, want POST", gotMethod)
	}
	if gotHeader != "probe-1" {
		t.Errorf("server saw header %q, want probe-1", gotHeader)
	}
	bodyStart, _ := pl["body_start"].(string)
	if !strings.Contains(bodyStart, "echo field=1;id") {
		t.Errorf("response body %q does not echo the request body", bodyStart)
	}
}

func TestHTTPRequestMethodAllowlist(t *testing.T) {
	s := testScope("127.0.0.1")
	res := (HTTPRequest{}).Run(testCtx, s, map[string]any{"url": "http://127.0.0.1/x", "method": "TRACE"})
	if res.Allowed {
		t.Error("TRACE method was allowed")
	}
}

func TestHTTPRequestScopeDenial(t *testing.T) {
	s := testScope("127.0.0.2")
	res := (HTTPRequest{}).Run(testCtx, s, map[string]any{"url": "http://127.0.0.1/x"})
	if res.Allowed {
		t.Error("out-of-scope http_request was allowed")
	}
}

// TestRateLimiterBurstThenThrottle asserts the token bucket: a burst of up to
// the capacity passes instantly, then traffic settles at the per-second rate;
// hosts do not share buckets.
func TestRateLimiterBurstThenThrottle(t *testing.T) {
	rl := newRateLimiter(10)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 25; i++ {
		if err := rl.Wait(ctx, "host-a"); err != nil {
			t.Fatalf("wait: %v", err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 1400*time.Millisecond {
		t.Errorf("25 requests at 10/s took %v, want >= ~1.5s after the burst", elapsed)
	}
	if err := rl.Wait(ctx, "host-b"); err != nil {
		t.Fatalf("wait for other host: %v", err)
	}
	if d := time.Since(start) - elapsed; d > 100*time.Millisecond {
		t.Errorf("host-b was throttled by host-a's bucket: %v", d)
	}
}

// TestRateLimiterHonoursContext asserts Wait returns when the context is done.
func TestRateLimiterHonoursContext(t *testing.T) {
	rl := newRateLimiter(1) // 1 token/s: the second wait must block
	rl.Wait(context.Background(), "h")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := rl.Wait(ctx, "h"); err == nil {
		t.Error("Wait returned despite an expired context")
	}
}
