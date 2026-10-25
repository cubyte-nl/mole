package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mole/internal/scope"
)

func TestNoteOutOfScopeNarrowsGate(t *testing.T) {
	s := testScope("localhost", "127.0.0.0/8")
	dir := t.TempDir()
	exclPath := filepath.Join(dir, "exclusions.yaml")
	if err := s.LoadExclusions(exclPath); err != nil {
		t.Fatalf("load sidecar: %v", err)
	}

	if ok, reason := s.CheckTarget(testCtx, "localhost", nil); !ok {
		t.Fatalf("localhost should start in scope: %s", reason)
	}

	res := NoteOutOfScope{}.Run(testCtx, s, map[string]any{"target": "localhost", "reason": "not part of the engagement"})
	if !res.Allowed {
		t.Fatalf("note should succeed: %s", res.Reason)
	}
	if res.Target != "localhost" {
		t.Errorf("result target = %q", res.Target)
	}

	// The gate now denies on this scope, and the sidecar was written.
	if ok, reason := s.CheckTarget(testCtx, "localhost", nil); ok {
		t.Fatalf("gate must deny the excluded target: %s", reason)
	}
	if _, err := os.Stat(exclPath); err != nil {
		t.Fatalf("sidecar must be written: %v", err)
	}
	// 127.0.0.1 must stay in scope: exclusions only narrow.
	if ok, reason := s.CheckTarget(testCtx, "127.0.0.1", nil); !ok {
		t.Errorf("127.0.0.1 must stay in scope: %s", reason)
	}
}

func TestNoteOutOfScopePersistsAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.yaml")
	exclPath := filepath.Join(dir, "exclusions.yaml")
	if err := os.WriteFile(scopePath, []byte(`name: unit-test
in_scope:
  - localhost
authorisation:
  basis: ctf-lab
  operator: t
  date: 2026-10-07
  confirmed: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	s1, err := scope.Load(scopePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.LoadExclusions(exclPath); err != nil {
		t.Fatal(err)
	}
	res := NoteOutOfScope{}.Run(testCtx, s1, map[string]any{"target": "localhost", "reason": "operator infra, not authorised"})
	if !res.Allowed {
		t.Fatalf("note should succeed: %s", res.Reason)
	}

	// A fresh scope load (the next mole run / mole check) must still deny.
	s2, err := scope.Load(scopePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.LoadExclusions(exclPath); err != nil {
		t.Fatal(err)
	}
	if ok, reason := s2.CheckTarget(testCtx, "localhost", nil); ok {
		t.Fatalf("reloaded scope must deny the excluded target: %s", reason)
	}
}

func TestNoteOutOfScopeRefusesInvalidArgs(t *testing.T) {
	s := testScope("localhost")
	if res := (NoteOutOfScope{}.Run(testCtx, s, map[string]any{"reason": "r"})); res.Allowed {
		t.Errorf("missing target must be refused: %s", res.Reason)
	}
	if res := (NoteOutOfScope{}.Run(testCtx, s, map[string]any{"target": "localhost"})); res.Allowed {
		t.Errorf("missing reason must be refused: %s", res.Reason)
	}
}

func TestNoteOutOfScopeRefusesOutOfScopeTarget(t *testing.T) {
	s := testScope("localhost")
	// example.org is not under any recorded in-scope pattern: the addendum
	// cannot be used to touch targets that were never in scope.
	res := NoteOutOfScope{}.Run(testCtx, s, map[string]any{"target": "example.org", "reason": "nope"})
	if res.Allowed {
		t.Fatal("out-of-scope target must be refused")
	}
	if !strings.Contains(res.Reason, "narrow") {
		t.Errorf("refusal should explain narrowing-only, got: %s", res.Reason)
	}
}

func TestNoteOutOfScopeRefusesCIDR(t *testing.T) {
	s := testScope("127.0.0.0/8")
	res := NoteOutOfScope{}.Run(testCtx, s, map[string]any{"target": "127.0.0.0/8", "reason": "nope"})
	if res.Allowed {
		t.Fatal("CIDR targets must be refused")
	}
}

func TestNoteOutOfScopeInRegistry(t *testing.T) {
	reg := NewRegistry(false, newLedger(t), newKB())
	if !registered(reg, "note_out_of_scope") {
		t.Fatal("note_out_of_scope must be registered")
	}
	s := testScope("localhost")
	if err := s.LoadExclusions(filepath.Join(t.TempDir(), "exclusions.yaml")); err != nil {
		t.Fatalf("load sidecar: %v", err)
	}
	res := reg.Run(testCtx, s, "note_out_of_scope", `{"target":"localhost","reason":"r"}`)
	if !res.Allowed {
		t.Fatalf("registry dispatch should succeed: %s", res.Reason)
	}
}
