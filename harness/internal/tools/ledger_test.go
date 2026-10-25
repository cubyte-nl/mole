package tools

import (
	"strings"
	"testing"

	"mole/internal/ledger"
)

func TestRecordFindingTool(t *testing.T) {
	l := newLedger(t)
	reg := NewRegistry(false, l, newKB())

	// Missing summary is rejected before anything is recorded.
	if res := reg.Run(testCtx, testScope("127.0.0.1"), "record_finding", `{}`); res.Allowed {
		t.Fatal("record_finding without summary was allowed")
	}

	res := reg.Run(testCtx, testScope("127.0.0.1"), "record_finding",
		`{"summary":"SSH open on 22/tcp","target":"127.0.0.1","source":"nmap 127.0.0.1","evidence":"22/tcp open ssh"}`)
	if !res.Allowed {
		t.Fatalf("record_finding denied: %s", res.Reason)
	}
	if res.Target != "127.0.0.1" {
		t.Errorf("target = %q, want 127.0.0.1", res.Target)
	}
	p, ok := res.Payload.(map[string]any)
	if !ok {
		t.Fatalf("payload type %T", res.Payload)
	}
	if p["id"] != "F1" {
		t.Errorf("payload id = %v, want F1", p["id"])
	}
	if p["status"] != "new" {
		t.Errorf("payload status = %v, want new", p["status"])
	}

	// The finding is persisted: a reopened ledger has it.
	l2, err := ledger.New(l.Path())
	if err != nil {
		t.Fatalf("reopen ledger: %v", err)
	}
	fs := l2.Findings()
	if len(fs) != 1 || fs[0].Summary != "SSH open on 22/tcp" || fs[0].Status != ledger.StatusNew {
		t.Errorf("persisted findings = %+v", fs)
	}
}

func TestUpdateFindingTool(t *testing.T) {
	l := newLedger(t)
	reg := NewRegistry(false, l, newKB())
	reg.Run(testCtx, testScope("127.0.0.1"), "record_finding",
		`{"summary":"SSH open on 22/tcp","target":"127.0.0.1","source":"nmap","evidence":"22/tcp open ssh"}`)

	// Missing id / status are rejected.
	if res := reg.Run(testCtx, testScope("127.0.0.1"), "update_finding", `{"status":"exploited"}`); res.Allowed {
		t.Fatal("update_finding without id was allowed")
	}
	if res := reg.Run(testCtx, testScope("127.0.0.1"), "update_finding", `{"id":"F1"}`); res.Allowed {
		t.Fatal("update_finding without status was allowed")
	}

	// An unknown status is rejected, listing the valid ones.
	if res := reg.Run(testCtx, testScope("127.0.0.1"), "update_finding",
		`{"id":"F1","status":"compromised"}`); res.Allowed {
		t.Fatal("update_finding with an unknown status was allowed")
	}

	// An unknown finding id is rejected.
	if res := reg.Run(testCtx, testScope("127.0.0.1"), "update_finding",
		`{"id":"F9","status":"exploited"}`); res.Allowed {
		t.Fatal("update_finding for an unknown finding was allowed")
	}

	// A valid update advances the status and records the exploitation link.
	res := reg.Run(testCtx, testScope("127.0.0.1"), "update_finding",
		`{"id":"f1","status":"exploited","exploit":"nuclei ssh-weak-password","note":""}`)
	if !res.Allowed {
		t.Fatalf("update_finding denied: %s", res.Reason)
	}
	if res.Target != "F1" {
		t.Errorf("target = %q, want F1", res.Target)
	}
	p, _ := res.Payload.(map[string]any)
	if p["status"] != "exploited" {
		t.Errorf("payload status = %v, want exploited", p["status"])
	}
	fs := l.Findings()
	if len(fs) != 1 || fs[0].Status != ledger.StatusExploited || fs[0].Exploit != "nuclei ssh-weak-password" {
		t.Errorf("findings = %+v", fs)
	}
	if out := l.Render(3); !strings.Contains(out, "→ nuclei ssh-weak-password") {
		t.Errorf("render missing exploitation link:\n%s", out)
	}
}
