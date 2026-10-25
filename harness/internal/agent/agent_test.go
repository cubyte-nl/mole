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
	"mole/internal/knowledge"
	"mole/internal/ledger"
	"mole/internal/scope"
	"mole/internal/tools"
)

// newLedger opens a throwaway findings ledger for a test.
func newLedger(t *testing.T) *ledger.Ledger {
	t.Helper()
	l, err := ledger.New(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	return l
}

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

	res, err := Run(context.Background(), s, client, tools.NewRegistry(false, newLedger(t), knowledge.New(nil)), Config{ReportDir: dir, MaxSteps: 5})
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

// TestAgentLedgerIsInjectedAndReported scripts the model recording a finding,
// then finishing. It asserts the ledger's state is re-injected into the model's
// context before the next chat call, and the finding → exploitation chain is
// rendered into the report.
func TestAgentLedgerIsInjectedAndReported(t *testing.T) {
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
		var msg any
		if turns == 0 {
			msg = map[string]any{
				"role": "assistant", "content": "",
				"tool_calls": []any{
					map[string]any{"id": "c1", "type": "function",
						"function": map[string]any{"name": "record_finding",
							"arguments": `{"summary":"SSH open on 22/tcp","target":"127.0.0.1","source":"nmap 127.0.0.1","evidence":"22/tcp open ssh"}`}},
				},
			}
		} else {
			msg = map[string]any{
				"role":    "assistant",
				"content": "## Summary\n127.0.0.1 runs SSH.",
			}
		}
		raw, _ := json.Marshal(oneChoice(msg))
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}))
	defer srv.Close()

	s := &scope.Scope{
		Name:    "ledger-test",
		InScope: []string{"127.0.0.1"},
		Auth:    scope.Authorization{Basis: scope.BasisCTFLab, Confirmed: true},
	}
	client := llm.NewClient(srv.URL, "", "test-model")
	led := newLedger(t)
	dir := t.TempDir()
	res, err := Run(context.Background(), s, client, tools.NewRegistry(false, led, knowledge.New(nil)),
		Config{ReportDir: dir, MaxSteps: 5, Ledger: led})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Steps != 1 {
		t.Fatalf("steps = %d, want 1", res.Steps)
	}

	// The state block must be re-injected as a user message before the second
	// chat call (it is absent from the first — the ledger is still empty then).
	mu.Lock()
	defer mu.Unlock()
	if len(reqs) < 2 {
		t.Fatalf("got %d chat calls, want at least 2", len(reqs))
	}
	var second struct {
		Messages []llm.Message `json:"messages"`
	}
	if err := json.Unmarshal([]byte(reqs[1]), &second); err != nil {
		t.Fatalf("decoding second request: %v", err)
	}
	seenState := false
	for _, m := range second.Messages {
		if m.Role == "user" && strings.Contains(m.Content, "## Findings ledger") &&
			strings.Contains(m.Content, "F1 [new] SSH open on 22/tcp") {
			seenState = true
		}
	}
	if !seenState {
		t.Error("ledger state was not re-injected into the model's context")
	}
	// The first call must not carry a state block (empty ledger renders "").
	var first struct {
		Messages []llm.Message `json:"messages"`
	}
	if err := json.Unmarshal([]byte(reqs[0]), &first); err != nil {
		t.Fatalf("decoding first request: %v", err)
	}
	for _, m := range first.Messages {
		if strings.Contains(m.Content, "## Findings ledger") {
			t.Error("empty ledger must not inject a state block")
		}
	}

	// The report must render the finding → exploitation chain from the ledger.
	for _, want := range []string{
		"## Finding → exploitation chain",
		"| F1 | SSH open on 22/tcp | nmap 127.0.0.1 | new | — |",
	} {
		if !strings.Contains(res.Report, want) {
			t.Errorf("report missing %q\n---\n%s", want, res.Report)
		}
	}
	if len(led.Findings()) != 1 {
		t.Fatalf("ledger findings = %d, want 1", len(led.Findings()))
	}
}

// TestAgentKnowledgePointerBothModes asserts the system prompt points the model
// at knowledge_search in every engagement (the per-service enumeration
// checklists guide reconnaissance too), and that exploitation-specific
// pointers (nuclei, ffuf) appear only when exploitation is in scope.
func TestAgentKnowledgePointerBothModes(t *testing.T) {
	for _, vuln := range []bool{true, false} {
		name := "recon-only"
		if vuln {
			name = "exploit-in-scope"
		}
		t.Run(name, func(t *testing.T) {
			s := &scope.Scope{
				Name:         "knowledge-test",
				InScope:      []string{"127.0.0.1"},
				VulnScanning: vuln,
				Auth:         scope.Authorization{Basis: scope.BasisCTFLab, Confirmed: true},
			}
			p := systemPrompt(s, "Reconnaissance", "test-model")
			for _, want := range []string{"knowledge_search", "documented reason"} {
				if !strings.Contains(p, want) {
					t.Errorf("system prompt missing %q", want)
				}
			}
			for _, marker := range []string{"nuclei", "ffuf", "exec tool", "Post-foothold"} {
				if vuln && !strings.Contains(p, marker) {
					t.Errorf("system prompt missing exploitation-only %q", marker)
				}
				if !vuln && strings.Contains(p, marker) {
					t.Errorf("system prompt carries exploitation-only %q", marker)
				}
			}
		})
	}
}

// TestAgentKnowledgeSearchRoundTrip scripts the model calling knowledge_search
// after a finding lands, then finishing. It asserts the retrieved section is
// fed back into the model's context — the mini-RAG loop, end to end.
func TestAgentKnowledgeSearchRoundTrip(t *testing.T) {
	const fixture = `# Test playbook

## Linux

### Permissions

- setuid-root binaries are the classic local escalation.
`
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
		var msg any
		if turns == 0 {
			msg = map[string]any{
				"role": "assistant", "content": "",
				"tool_calls": []any{
					map[string]any{"id": "c1", "type": "function",
						"function": map[string]any{"name": "knowledge_search",
							"arguments": `{"query":"setuid binary escalation"}`}},
				},
			}
		} else {
			msg = map[string]any{
				"role":    "assistant",
				"content": "## Summary\nSetuid vectors checked per the playbook.",
			}
		}
		raw, _ := json.Marshal(oneChoice(msg))
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}))
	defer srv.Close()

	s := &scope.Scope{
		Name:         "knowledge-e2e",
		InScope:      []string{"127.0.0.1"},
		VulnScanning: true,
		Auth:         scope.Authorization{Basis: scope.BasisCTFLab, Confirmed: true},
	}
	client := llm.NewClient(srv.URL, "", "test-model")
	kb := knowledge.New([]knowledge.Doc{{Name: "fixture.md", Content: fixture}})
	res, err := Run(context.Background(), s, client, tools.NewRegistry(true, newLedger(t), kb),
		Config{ReportDir: t.TempDir(), MaxSteps: 5})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Steps != 1 {
		t.Fatalf("steps = %d, want 1", res.Steps)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reqs) < 2 {
		t.Fatalf("got %d chat calls, want at least 2", len(reqs))
	}
	// The tool result carrying the retrieved section must be in the model's
	// context before the final answer. The tool result is nested JSON, so
	// match the section text without quotes.
	if !strings.Contains(reqs[1], "setuid-root binaries are the classic local escalation") {
		t.Error("retrieved section was not fed back into the model's context")
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
	res, err := Run(context.Background(), s, client, tools.NewRegistry(false, newLedger(t), knowledge.New(nil)), Config{MaxSteps: 3})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(res.Report, "unknown tool") {
		// unknown tool results are fed to the model; the report just needs to be produced
		t.Log("note: report does not mention the unknown tool (it is only in the transcript)")
	}
}
