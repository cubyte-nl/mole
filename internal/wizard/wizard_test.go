package wizard

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// happyInput drives a full run: name, own-infra basis, operator, one in-scope
// domain, one out-of-scope entry, two ports, no vulnerability scanning, and
// the final typed-YES confirmation.
const happyInput = "cubyte\n1\nsven\ncubyte.nl\nnode2.cubby.nl\n443,8080\nno\nYES\n"

func runWizard(t *testing.T, input string, o Options) (string, error) {
	t.Helper()
	if o.Dir == "" {
		o.Dir = t.TempDir()
	}
	if o.In == nil {
		o.In = strings.NewReader(input)
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	return Run(o)
}

func readScope(t *testing.T, path string) (ScopeFile, string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s ScopeFile
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatalf("written scope.yaml does not parse: %v\n%s", err, raw)
	}
	return s, string(raw)
}

func assertNoFile(t *testing.T, dir, name string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, name, "scope.yaml")); !os.IsNotExist(err) {
		t.Fatalf("scope.yaml written despite abort: %v", err)
	}
}

func TestRunWritesScope(t *testing.T) {
	dir := t.TempDir()
	path, err := runWizard(t, happyInput, Options{Dir: dir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := filepath.Join(dir, "cubyte", "scope.yaml"); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	s, raw := readScope(t, path)
	if s.Name != "cubyte" || s.InScope[0] != "cubyte.nl" ||
		s.OutOfScope[0] != "node2.cubby.nl" ||
		len(s.Ports) != 2 || s.Ports[0] != 443 || s.Ports[1] != 8080 {
		t.Errorf("scope record wrong: %+v", s)
	}
	if s.VulnScanning {
		t.Errorf("vuln_scanning = true, want the reconnaissance-only default")
	}
	if s.Auth.Basis != BasisOwnInfra || s.Auth.Operator != "sven" || !s.Auth.Confirmed {
		t.Errorf("authorisation record wrong: %+v", s.Auth)
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(s.Auth.Date) {
		t.Errorf("date %q is not YYYY-MM-DD", s.Auth.Date)
	}
	// The launcher must write the canonical key, never the legacy alias.
	if strings.Contains(raw, "exploit") {
		t.Errorf("wrote the legacy exploit key:\n%s", raw)
	}
	if !strings.Contains(raw, "in_scope:") || !strings.Contains(raw, "authorisation:") {
		t.Errorf("missing canonical keys:\n%s", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("scope.yaml mode = %o, want 600", perm)
	}
}

func TestRunVulnScanningEnabled(t *testing.T) {
	dir := t.TempDir()
	// "yes" to the opt-in, then the typed YES.
	path, err := runWizard(t, "cubyte\n1\nsven\ncubyte.nl\n\n\nyes\nYES\nYES\n", Options{Dir: dir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	s, raw := readScope(t, path)
	if !s.VulnScanning {
		t.Errorf("vuln_scanning = false, want true:\n%s", raw)
	}
}

func TestRunVulnScanningRefusedStaysDisabled(t *testing.T) {
	dir := t.TempDir()
	path, err := runWizard(t, "cubyte\n1\nsven\ncubyte.nl\n\n\nyes\nno\nYES\n", Options{Dir: dir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	s, raw := readScope(t, path)
	if s.VulnScanning {
		t.Errorf("vuln_scanning enabled without typed YES:\n%s", raw)
	}
}

func TestRunClientBasisRecordsClient(t *testing.T) {
	dir := t.TempDir()
	path, err := runWizard(t, "acme\n2\nAcme Corp\nSOW-42\nsven\nacme.example\n\n\nno\nYES\n", Options{Dir: dir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	s, _ := readScope(t, path)
	if s.Auth.Basis != BasisClient || s.Auth.Client != "Acme Corp" || s.Auth.Reference != "SOW-42" {
		t.Errorf("client record wrong: %+v", s.Auth)
	}
}

func TestRunClientBasisWithoutReferenceAborts(t *testing.T) {
	dir := t.TempDir()
	if _, err := runWizard(t, "acme\n2\nAcme Corp\n\nsven\nacme.example\n\n\nno\nYES\n", Options{Dir: dir}); err == nil {
		t.Fatal("client engagement without a reference: want error, got nil")
	}
	assertNoFile(t, dir, "acme")
}

func TestRunAborts(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"no name":    "\n1\nsven\ncubyte.nl\n\n\nno\nYES\n",
		"bad basis":  "cubyte\n9\nsven\ncubyte.nl\n\n\nno\nYES\n",
		"empty scope": "cubyte\n1\nsven\n\n\n\nno\nYES\n",
		"bad port":   "cubyte\n1\nsven\ncubyte.nl\n\n\n99999\nno\nYES\n",
		"no confirm": "cubyte\n1\nsven\ncubyte.nl\n\n\nno\nno\n",
	}
	for name, input := range cases {
		if _, err := runWizard(t, input, Options{Dir: dir}); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
	assertNoFile(t, dir, "cubyte")
	assertNoFile(t, dir, "acme")
}

func TestRunDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	path, err := runWizard(t, happyInput, Options{Dir: dir, Dry: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := filepath.Join(dir, "cubyte", "scope.yaml"); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	assertNoFile(t, dir, "cubyte")
}

func TestRunPresetName(t *testing.T) {
	// An empty answer keeps the prefilled name.
	path, err := runWizard(t, "\n1\nsven\ncubyte.nl\n\n\nno\nYES\n", Options{Dir: t.TempDir(), PresetName: "preset"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if base := filepath.Base(filepath.Dir(path)); base != "preset" {
		t.Fatalf("engagement dir = %q, want preset", base)
	}
}
