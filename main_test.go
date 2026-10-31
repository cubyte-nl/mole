package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mole/internal/wizard"

	"gopkg.in/yaml.v3"
)

const scopeYAML = `name: cubyte
in_scope:
    - cubyte.nl
out_of_scope:
    - node2.cubby.nl
    - 188.165.204.91
ports: []
authorisation:
    basis: own-infra
    operator: sven
    date: "2026-10-07"
    confirmed: true
`

// runAskVulnScanning writes an engagement tree, drives askVulnScanning with
// the given piped input, and returns the resulting scope.yaml content.
func runAskVulnScanning(t *testing.T, input, scope string, dry bool) string {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"cubyte/scope.yaml": scope})
	r := bufio.NewReader(strings.NewReader(input))
	if err := askVulnScanning(r, dir, &Config{Engagement: "cubyte"}, dry); err != nil {
		t.Fatalf("askVulnScanning: %v", err)
	}
	out, err := os.ReadFile(filepath.Join(dir, "cubyte", "scope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func mustScope(t *testing.T, s string) wizard.ScopeFile {
	t.Helper()
	var got wizard.ScopeFile
	if err := yaml.Unmarshal([]byte(s), &got); err != nil {
		t.Fatalf("rewritten scope.yaml does not parse: %v\n%s", err, s)
	}
	return got
}

func TestAskVulnScanningEnableWithConfirmation(t *testing.T) {
	out := runAskVulnScanning(t, "yes\nYES\n", scopeYAML, false)
	got := mustScope(t, out)
	if !got.VulnScanning {
		t.Errorf("vuln_scanning = false, want true")
	}
	// The launcher must write the canonical key, not the legacy alias.
	if strings.Contains(out, "exploit") {
		t.Errorf("rewrote the legacy exploit key instead of vuln_scanning:\n%s", out)
	}
	// The rest of the record must round-trip unchanged.
	if got.Name != "cubyte" || got.InScope[0] != "cubyte.nl" ||
		len(got.OutOfScope) != 2 || !got.Auth.Confirmed || got.Auth.Operator != "sven" {
		t.Errorf("scope record corrupted on rewrite: %+v", got)
	}
}

func TestAskVulnScanningEnableRefused(t *testing.T) {
	out := runAskVulnScanning(t, "yes\nno\n", scopeYAML, false)
	if out != scopeYAML {
		t.Errorf("file modified without typed YES confirmation:\n%s", out)
	}
}

func TestAskVulnScanningDisableWithConfirmation(t *testing.T) {
	// A canonical vuln_scanning: true file must read as enabled and disable.
	out := runAskVulnScanning(t, "no\ny\n", "vuln_scanning: true\n"+scopeYAML, false)
	got := mustScope(t, out)
	if got.VulnScanning {
		t.Errorf("vuln_scanning = true, want false after disable")
	}
	if got.Name != "cubyte" || got.InScope[0] != "cubyte.nl" {
		t.Errorf("scope record corrupted on rewrite: %+v", got)
	}
}

func TestAskVulnScanningDisableCancelled(t *testing.T) {
	in := "vuln_scanning: true\n" + scopeYAML
	out := runAskVulnScanning(t, "no\nn\n", in, false)
	if out != in {
		t.Errorf("file modified without disable confirmation:\n%s", out)
	}
}

func TestAskVulnScanningKeepDefault(t *testing.T) {
	// An enabled engagement, left at the default answer, stays enabled and is
	// not rewritten — the launcher's displayed state matches what the agent runs.
	in := "vuln_scanning: true\n" + scopeYAML
	out := runAskVulnScanning(t, "\n", in, false)
	if out != in {
		t.Errorf("file modified for unchanged state:\n%s", out)
	}
}

func TestAskVulnScanningLegacyExploitMigrates(t *testing.T) {
	// A legacy exploit: true file reads as enabled; disabling it must remove
	// the legacy key rather than leave the engagement silently opted in.
	out := runAskVulnScanning(t, "no\ny\n", "exploit: true\n"+scopeYAML, false)
	if mustScope(t, out).VulnScanning {
		t.Errorf("vuln_scanning = true, want false after disabling a legacy opt-in")
	}
	if strings.Contains(out, "exploit") {
		t.Errorf("legacy exploit key survived the rewrite:\n%s", out)
	}
}

func TestAskVulnScanningDryRun(t *testing.T) {
	out := runAskVulnScanning(t, "yes\nYES\n", scopeYAML, true)
	if out != scopeYAML {
		t.Errorf("dry-run modified scope.yaml:\n%s", out)
	}
}

func TestAskVulnScanningNoEngagement(t *testing.T) {
	// No engagement under dir: the wizard offer is declined, scope kept, and
	// it returns without error.
	dir := t.TempDir()
	r := bufio.NewReader(strings.NewReader("no\n"))
	if err := askVulnScanning(r, dir, &Config{}, false); err != nil {
		t.Fatalf("askVulnScanning should not fail on a missing engagement: %v", err)
	}
}

func TestAskVulnScanningOffersWizard(t *testing.T) {
	// No engagement under dir: accept the inline offer and drive the wizard
	// to completion; scope.yaml must be created with mode 0600, and the
	// follow-up step-4 question keeps the default (disabled).
	const wizardInput = "cubyte\n1\nsven\ncubyte.nl\nnode2.cubby.nl\n443,8080\nno\nYES\n"
	dir := t.TempDir()
	r := bufio.NewReader(strings.NewReader("y\n" + wizardInput + "\n"))
	if err := askVulnScanning(r, dir, &Config{}, false); err != nil {
		t.Fatalf("askVulnScanning: %v", err)
	}
	path := filepath.Join(dir, "cubyte", "scope.yaml")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("wizard did not write scope.yaml: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("scope.yaml mode = %o, want 600", perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := mustScope(t, string(raw))
	if s.Name != "cubyte" || len(s.InScope) != 1 || s.InScope[0] != "cubyte.nl" {
		t.Errorf("scope record wrong: %+v", s)
	}
	if s.VulnScanning {
		t.Errorf("vuln_scanning = true, want the reconnaissance-only default")
	}
}

func TestResolveEngagement(t *testing.T) {
	// Single engagement is inferred.
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"cubyte/scope.yaml": scopeYAML,
		"notes/readme.md":   "no scope here",
	})
	name, err := resolveEngagement(dir, "")
	if err != nil || name != "cubyte" {
		t.Fatalf("single engagement: got %q, %v; want cubyte", name, err)
	}
	// Explicit name is honoured even with several engagements.
	writeTree(t, dir, map[string]string{"other/scope.yaml": scopeYAML})
	name, err = resolveEngagement(dir, "other")
	if err != nil || name != "other" {
		t.Fatalf("explicit name: got %q, %v", name, err)
	}
	// Ambiguity is an error.
	if _, err := resolveEngagement(dir, ""); err == nil {
		t.Fatal("multiple engagements: want error, got nil")
	}
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadDockerignore(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".dockerignore")
	if err := os.WriteFile(p, []byte(".git\nengagement/\n/mole\nDockerfile\n!Dockerfile.bak\n# comment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ignored, err := loadDockerignore(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		rel  string
		want bool
	}{
		{".git", true},            // bare name, file at root
		{".git/hooks/x.sh", true}, // bare name matches at any depth
		{"engagement/", true},     // trailing-slash rule only matches dirs
		{"engagement/scope.yaml", true},
		{"engagement", false},     // file named engagement is not excluded
		{"mole", true},            // root-anchored rule
		{"sub/mole", false},       // anchored rule does not match deep paths
		{"Dockerfile", true},      // excluded by its own rule
		{"Dockerfile.bak", false}, // re-included by the ! rule
		{"internal/Dockerfile", true},
		{"main.go", false},
	}
	for _, c := range cases {
		if got := ignored(c.rel); got != c.want {
			t.Errorf("ignored(%q) = %v, want %v", c.rel, got, c.want)
		}
	}
}

func TestContextVersionStableAndSensitive(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"Dockerfile":      "FROM scratch",
		"main.go":         "package main",
		".dockerignore":   "engagement/",
		"engagement/x":    "data",
		"internal/app.go": "package app",
	})
	v1, err := contextVersion(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(v1) != 12 {
		t.Fatalf("version length = %d, want 12", len(v1))
	}
	// Untouched tree yields the same version (ignoring mtimes).
	v2, err := contextVersion(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 {
		t.Fatalf("version changed without content change: %s -> %s", v1, v2)
	}
	// Changing any part of the build changes the version.
	changes := map[string]string{
		"Dockerfile":      "FROM alpine",
		"main.go":         "package main // edited",
		".dockerignore":   "engagement/\nscratch/",
		"internal/app.go": "package app // edited",
	}
	for name, content := range changes {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		v, err := contextVersion(dir)
		if err != nil {
			t.Fatal(err)
		}
		if v == v1 {
			t.Errorf("version unchanged after editing %s", name)
		}
	}
}

func TestContextVersionIgnoresExcludedFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"Dockerfile":    "FROM scratch",
		"main.go":       "package main",
		".dockerignore": "engagement/",
		"engagement/x":  "data",
	})
	v1, err := contextVersion(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Engagement data is .dockerignored; changing it must not bump the version.
	if err := os.WriteFile(filepath.Join(dir, "engagement/x"), []byte("more data"), 0o644); err != nil {
		t.Fatal(err)
	}
	v2, err := contextVersion(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 {
		t.Fatalf("version changed for .dockerignored content: %s -> %s", v1, v2)
	}
}
