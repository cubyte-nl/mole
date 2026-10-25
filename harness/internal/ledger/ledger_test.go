package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTempLedger(t *testing.T) *Ledger {
	t.Helper()
	l, err := New(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func TestRecordAndRender(t *testing.T) {
	l := newTempLedger(t)
	f, err := l.Record("SSH open on 22/tcp", "127.0.0.1", "nmap 127.0.0.1", "22/tcp open ssh")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if f.ID != "F1" || f.Status != StatusNew {
		t.Fatalf("finding = %+v, want F1/new", f)
	}
	if _, err := l.Record("Second finding", "", "", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}

	out := l.Render(7)
	for _, want := range []string{
		"## Findings ledger (step 7)",
		"F1 [new] SSH open on 22/tcp — 127.0.0.1 (src: nmap 127.0.0.1)",
		"F2 [new] Second finding",
		"Awaiting follow-up: F1, F2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Render missing %q\n---\n%s", want, out)
		}
	}
	if l.Empty() {
		t.Error("Empty = true with findings recorded")
	}
}

func TestRenderEmptyLedger(t *testing.T) {
	l := newTempLedger(t)
	if !l.Empty() {
		t.Fatal("Empty = false on a fresh ledger")
	}
	if l.Render(1) != "" {
		t.Error("Render on an empty ledger must be \"\"")
	}
	if l.RenderReport() != "" {
		t.Error("RenderReport on an empty ledger must be \"\"")
	}
}

func TestUpdateLifecycle(t *testing.T) {
	l := newTempLedger(t)
	if _, err := l.Record("SSH open on 22/tcp", "127.0.0.1", "nmap", "22/tcp open ssh"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	f, err := l.Update("F1", "exploited", "nuclei ssh-weak-password", "weak password accepted")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if f.Status != StatusExploited || f.Exploit == "" {
		t.Fatalf("updated finding = %+v", f)
	}

	out := l.Render(2)
	if !strings.Contains(out, "F1 [exploited] SSH open on 22/tcp — 127.0.0.1 (src: nmap) → nuclei ssh-weak-password") {
		t.Errorf("Render missing exploited chain\n---\n%s", out)
	}
	if strings.Contains(out, "Awaiting follow-up") {
		t.Errorf("no open finding should list follow-up\n---\n%s", out)
	}

	rep := l.RenderReport()
	for _, want := range []string{
		"## Finding → exploitation chain",
		"| F1 | SSH open on 22/tcp | nmap | exploited | nuclei ssh-weak-password |",
	} {
		if !strings.Contains(rep, want) {
			t.Errorf("RenderReport missing %q\n---\n%s", want, rep)
		}
	}
}

func TestUpdateUnknownIDAndStatus(t *testing.T) {
	l := newTempLedger(t)
	if _, err := l.Update("F9", "exploited", "", ""); err == nil {
		t.Fatal("Update on unknown ID must fail")
	}
	if _, err := l.Update("f1", "compromised", "", ""); err == nil {
		t.Fatal("Update with an unknown status must fail")
	}
	if _, ok := ParseStatus("exploited"); !ok {
		t.Error("ParseStatus(exploited) = false, want true")
	}
	if _, ok := ParseStatus(" "); ok {
		t.Error("ParseStatus(whitespace) = true, want false")
	}
}

func TestRecordRequiresSummary(t *testing.T) {
	l := newTempLedger(t)
	if _, err := l.Record("   ", "t", "s", "e"); err == nil {
		t.Fatal("Record with a blank summary must fail")
	}
}

func TestResumeKeepsFindingsAndIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "ledger.json")
	l, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := l.Record("first", "127.0.0.1", "nmap", "22/tcp open ssh"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := l.Record("second", "", "", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// Reopen: a resumed engagement keeps its working memory.
	l2, err := New(path)
	if err != nil {
		t.Fatalf("New (resume): %v", err)
	}
	if got := len(l2.Findings()); got != 2 {
		t.Fatalf("resumed findings = %d, want 2", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading ledger file: %v", err)
	}
	if !strings.Contains(string(raw), "\"next_id\": 3") {
		t.Errorf("ledger file missing next_id 3\n---\n%s", raw)
	}
	f, err := l2.Record("third", "", "", "")
	if err != nil {
		t.Fatalf("Record after resume: %v", err)
	}
	if f.ID != "F3" {
		t.Fatalf("ID after resume = %s, want F3", f.ID)
	}
}
