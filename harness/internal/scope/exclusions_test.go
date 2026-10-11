package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withSidecar points s at a (missing) exclusions.yaml in a fresh temp dir,
// the way main.go wires every loaded scope.
func withSidecar(t *testing.T, s *Scope) {
	t.Helper()
	if err := s.LoadExclusions(filepath.Join(t.TempDir(), "exclusions.yaml")); err != nil {
		t.Fatalf("load sidecar: %v", err)
	}
}

func TestExcludeNarrowsName(t *testing.T) {
	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"localhost"}, Auth: confirmed(BasisCTFLab)})
	withSidecar(t, s)
	if ok, _ := s.CheckTarget(ctx, "localhost", nil); !ok {
		t.Fatal("localhost should start in scope")
	}
	if err := s.Exclude("localhost", "agent judged out of scope"); err != nil {
		t.Fatalf("exclude: %v", err)
	}
	if ok, reason := s.CheckTarget(ctx, "localhost", nil); ok {
		t.Fatalf("localhost should be denied after exclusion, got: %s", reason)
	}
	if len(s.Exclusions) != 1 || s.Exclusions[0].Source != "agent" {
		t.Errorf("exclusion not recorded correctly: %+v", s.Exclusions)
	}
}

func TestExcludeNarrowsIP(t *testing.T) {
	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"127.0.0.0/8"}, Auth: confirmed(BasisOwnInfra)})
	withSidecar(t, s)
	if err := s.Exclude("127.0.0.2", "not part of the engagement"); err != nil {
		t.Fatalf("exclude: %v", err)
	}
	if ok, reason := s.CheckTarget(ctx, "127.0.0.2", nil); ok {
		t.Errorf("127.0.0.2 should be denied, got: %s", reason)
	}
	if ok, reason := s.CheckTarget(ctx, "127.0.0.1", nil); !ok {
		t.Errorf("127.0.0.1 should stay in scope, got: %s", reason)
	}
}

func TestExcludeGuards(t *testing.T) {
	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"localhost", "127.0.0.0/8"}, Auth: confirmed(BasisCTFLab)})
	withSidecar(t, s)

	cases := []struct {
		name   string
		target string
		want   string
	}{
		{"empty", "   ", "empty"},
		{"cidr", "127.0.0.0/8", "CIDR"},
		{"not-in-scope", "example.org", "narrow"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := s.Exclude(c.target, "r"); err == nil {
				t.Fatalf("Exclude(%q) should fail", c.target)
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q should mention %q", err, c.want)
			}
		})
	}
	if len(s.Exclusions) != 0 {
		t.Errorf("failed exclusions must not be recorded: %+v", s.Exclusions)
	}
}

func TestExcludeNoSidecarRollsBack(t *testing.T) {
	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"localhost"}, Auth: confirmed(BasisCTFLab)})
	// No sidecar configured (LoadExclusions was never called).
	if err := s.Exclude("localhost", "r"); err == nil {
		t.Fatal("Exclude without a sidecar must fail")
	}
	if len(s.Exclusions) != 0 {
		t.Errorf("in-memory exclusion must be rolled back: %+v", s.Exclusions)
	}
}

func TestExcludePersistFailureRollsBack(t *testing.T) {
	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"localhost"}, Auth: confirmed(BasisCTFLab)})
	dir := t.TempDir()
	// Path under a non-existent directory guarantees the write fails.
	s.ExclusionsPath = filepath.Join(dir, "no-such-dir", "exclusions.yaml")
	if err := s.Exclude("localhost", "r"); err == nil {
		t.Fatal("persist failure must surface")
	}
	if len(s.Exclusions) != 0 {
		t.Errorf("in-memory exclusion must be rolled back on persist failure: %+v", s.Exclusions)
	}
}

func TestExcludeIdempotent(t *testing.T) {
	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"localhost"}, Auth: confirmed(BasisCTFLab)})
	withSidecar(t, s)
	for i := 0; i < 3; i++ {
		if err := s.Exclude("localhost", "r"); err != nil {
			t.Fatalf("duplicate exclude %d: %v", i, err)
		}
	}
	if len(s.Exclusions) != 1 {
		t.Errorf("duplicate excludes must be a no-op, got %d entries", len(s.Exclusions))
	}
}

func TestExclusionsPersistAndReload(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.yaml")
	exclPath := filepath.Join(dir, "exclusions.yaml")

	if err := os.WriteFile(scopePath, []byte(`name: e
in_scope:
  - localhost
  - 127.0.0.0/8
authorisation:
  basis: ctf-lab
  operator: t
  date: 2026-10-06
  confirmed: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"localhost"}, Auth: confirmed(BasisCTFLab)})
	if err := s.LoadExclusions(exclPath); err != nil {
		t.Fatalf("load missing sidecar: %v", err)
	}
	if err := s.Exclude("localhost", "agent judged out of scope"); err != nil {
		t.Fatalf("exclude: %v", err)
	}
	data, err := os.ReadFile(exclPath)
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	if !strings.Contains(string(data), "localhost") {
		t.Errorf("sidecar should record the target, got: %s", data)
	}

	// A fresh load of the same scope file must inherit the exclusion: the
	// gate enforces it on every subsequent run.
	s2, err := Load(scopePath)
	if err != nil {
		t.Fatalf("reload scope: %v", err)
	}
	if err := s2.LoadExclusions(exclPath); err != nil {
		t.Fatalf("reload exclusions: %v", err)
	}
	if ok, reason := s2.CheckTarget(ctx, "localhost", nil); ok {
		t.Fatalf("reloaded scope must deny the excluded target, got: %s", reason)
	}
	if ok, reason := s2.CheckTarget(ctx, "127.0.0.1", nil); !ok {
		t.Errorf("127.0.0.1 must stay in scope, got: %s", reason)
	}
	// scope.yaml itself must be untouched by the exclusion.
	scopeRaw, err := os.ReadFile(scopePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(scopeRaw), "exclusion") {
		t.Errorf("scope.yaml must never be modified by exclusions, got: %s", scopeRaw)
	}
}

func TestLoadExclusionsMissingFileIsOK(t *testing.T) {
	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"localhost"}, Auth: confirmed(BasisCTFLab)})
	if err := s.LoadExclusions(filepath.Join(t.TempDir(), "nope.yaml")); err != nil {
		t.Fatalf("missing sidecar is not an error: %v", err)
	}
}

func TestDescribeShowsExclusions(t *testing.T) {
	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"localhost", "127.0.0.0/8"}, Auth: confirmed(BasisCTFLab)})
	withSidecar(t, s)
	before := s.Describe()
	if strings.Contains(before, "Exclusions") {
		t.Errorf("Describe must not mention exclusions when there are none:\n%s", before)
	}
	if err := s.Exclude("localhost", "r"); err != nil {
		t.Fatalf("exclude: %v", err)
	}
	after := s.Describe()
	if !strings.Contains(after, "Exclusions") || !strings.Contains(after, "localhost") {
		t.Errorf("Describe must list exclusions:\n%s", after)
	}
}
