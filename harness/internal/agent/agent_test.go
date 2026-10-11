package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cubyte-nl/agent-core/llm"
	"mole/internal/scope"
	"mole/internal/tools"
)

// newFakeLLM scripts the model: dns_lookup, then an out-of-scope http_probe,
// then a final report. It records every request body for assertions.
func newFakeLLM(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var reqs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []llm.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		body, _ := json.Marshal(req)
		mu.Lock()
		reqs = append(reqs, string(body))
		mu.Unlock()

		turns := 0
		for _, m := range req.Messages {
			if m.Role == "tool" {
				turns++
			}
		}
		var resp any
		switch {
		case turns == 0:
			resp = oneChoice(map[string]any{
				"role": "assistant", "content": "",
				"tool_calls": []any{
					map[string]any{"id": "c1", "type": "function",
						"function": map[string]any{"name": "dns_lookup", "arguments": `{"host":"127.0.0.1"}`}},
				},
			})
		case turns == 1:
			resp = oneChoice(map[string]any{
				"role": "assistant", "content": "",
				"tool_calls": []any{
					map[string]any{"id": "c2", "type": "function",
						"function": map[string]any{"name": "http_probe", "arguments": `{"url":"http://example.org/"}`}},
				},
			})
		default:
			resp = oneChoice(map[string]any{
				"role":    "assistant",
				"content": "## Summary\nAll in-scope targets checked; 127.0.0.1 is live.",
			})
		}
		raw, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}))
	return srv, &reqs
}

func oneChoice(msg any) any {
	return map[string]any{"choices": []any{map[string]any{"message": msg, "finish_reason": "stop"}}}
}

func TestAgentGatesToolsAndWritesReport(t *testing.T) {
	srv, reqs := newFakeLLM(t)
	defer srv.Close()

	dir := t.TempDir()
	s := &scope.Scope{
		Name:       "e2e-test",
		InScope:    []string{"127.0.0.1"},
		OutOfScope: []string{"example.org"},
		Auth:       scope.Authorization{Basis: scope.BasisCTFLab, Operator: "t", Date: "2026-10-06", Confirmed: true},
	}
	client := llm.NewClient(srv.URL, "", "test-model")

	res, err := Run(context.Background(), s, client, tools.NewRegistry(false), Config{ReportDir: dir, MaxSteps: 5})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Steps != 2 {
		t.Fatalf("steps = %d, want 2", res.Steps)
	}

	raw, err := os.ReadFile(res.ReportPath)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	rep := string(raw)
	for _, want := range []string{
		"## Authorisation",
		"Basis      : ctf-lab",
		"In scope     : 127.0.0.1",
		"All in-scope targets checked",
	} {
		if !strings.Contains(rep, want) {
			t.Errorf("report missing %q\n---\n%s", want, rep)
		}
	}

	// The out-of-scope probe must have been denied by the gate, and the denial
	// must have been fed back to the model (present in a later request). The
	// tool result is nested JSON, so match the reason text without quotes.
	seenInRequest := false
	for _, req := range *reqs {
		if strings.Contains(req, `example.org is explicitly out of scope`) {
			seenInRequest = true
		}
	}
	if !seenInRequest {
		t.Error("gate denial for example.org was not fed back to the model")
	}

	// Transcript: a JSONL audit trail next to the report, with start/finish
	// events and the full conversation (including the denial).
	var tpath string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "transcript-") && strings.HasSuffix(e.Name(), ".jsonl") {
			tpath = filepath.Join(dir, e.Name())
		}
	}
	if tpath == "" {
		t.Fatal("no transcript file written")
	}
	traw, err := os.ReadFile(tpath)
	if err != nil {
		t.Fatalf("reading transcript: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(traw)), "\n")
	var first, last map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("transcript first line: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatalf("transcript last line: %v", err)
	}
	if first["event"] != "start" || first["engagement"] != "e2e-test" {
		t.Errorf("first line = %v, want start event", first)
	}
	if last["event"] != "finish" || last["report_path"] != res.ReportPath {
		t.Errorf("last line = %v, want finish event with report path", last)
	}
	if !strings.Contains(string(traw), "example.org is explicitly out of scope") {
		t.Error("transcript does not record the gate denial")
	}
}

func TestAgentUnknownToolIsReportedNotFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []llm.Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		turns := 0
		for _, m := range req.Messages {
			if m.Role == "tool" {
				turns++
			}
		}
		var msg any
		if turns == 0 {
			msg = map[string]any{
				"role": "assistant", "content": "",
				"tool_calls": []any{
					map[string]any{"id": "c1", "type": "function",
						"function": map[string]any{"name": "dropbox", "arguments": `{}`}},
				},
			}
		} else {
			msg = map[string]any{"role": "assistant", "content": "## Summary\ndone"}
		}
		raw, _ := json.Marshal(oneChoice(msg))
		w.Write(raw)
	}))
	defer srv.Close()

	s := &scope.Scope{
		Name:    "e2e-test",
		InScope: []string{"127.0.0.1"},
		Auth:    scope.Authorization{Basis: scope.BasisCTFLab, Confirmed: true},
	}
	client := llm.NewClient(srv.URL, "", "test-model")
	res, err := Run(context.Background(), s, client, tools.NewRegistry(false), Config{MaxSteps: 3})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(res.Report, "unknown tool") {
		// unknown tool results are fed to the model; the report just needs to be produced
		t.Log("note: report does not mention the unknown tool (it is only in the transcript)")
	}
}
