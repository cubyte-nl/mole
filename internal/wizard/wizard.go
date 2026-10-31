// Package wizard implements the interactive startup scoping. It asks targeted
// questions and writes a binding scope.yaml. This is the authorisation step:
// without the confirmation here, nothing runs — not the tools, not the agent.
//
// This is a copy of harness/internal/wizard: the launcher and the harness are
// separate Go modules with the same module path, and the image build only
// sees the harness/ context, so the package cannot be shared. Keep the prompt
// flow and the written scope.yaml format in sync with the harness copy —
// wizard_test.go pins the format.
package wizard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Authorisation bases (mirror harness/internal/scope).
const (
	BasisOwnInfra = "own-infra"
	BasisClient   = "client-engagement"
	BasisCTFLab   = "ctf-lab"
)

// ScopeFile mirrors the persisted fields of harness/internal/scope.Scope, in
// the same field order, so a scope written here is byte-compatible with one
// the harness writes.
type ScopeFile struct {
	Name         string     `yaml:"name"`
	InScope      []string   `yaml:"in_scope"`
	OutOfScope   []string   `yaml:"out_of_scope,omitempty"`
	Ports        []int      `yaml:"ports,omitempty"`
	VulnScanning bool       `yaml:"vuln_scanning,omitempty"`
	Auth         AuthRecord `yaml:"authorisation"`
}

// AuthRecord mirrors scope.Authorization.
type AuthRecord struct {
	Basis     string `yaml:"basis"`
	Operator  string `yaml:"operator"`
	Date      string `yaml:"date"`
	Reference string `yaml:"reference,omitempty"`
	Client    string `yaml:"client,omitempty"`
	Confirmed bool   `yaml:"confirmed"`
}

// Options configures a wizard run.
type Options struct {
	Dir        string // engagement directory
	PresetName string // prefills the engagement-name question
	Dry        bool   // print what would be written, write nothing
	In         io.Reader
	Out        io.Writer
}

// Run walks the operator through scoping and writes <dir>/<name>/scope.yaml.
// It returns the path of the written file (the would-be path in dry mode).
func Run(o Options) (string, error) {
	in := bufio.NewReader(o.In)
	out := o.Out
	ask := func(label string) string {
		fmt.Fprintf(out, "%s ", label)
		line, _ := in.ReadString('\n')
		return strings.TrimSpace(line)
	}
	askList := func(label string) []string {
		raw := ask(label)
		var list []string
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				list = append(list, part)
			}
		}
		return list
	}

	fmt.Fprintln(out, "== MOLE scoping ==")
	fmt.Fprintln(out)
	label := "Engagement name: "
	if o.PresetName != "" {
		label = "Engagement name [" + o.PresetName + "]: "
	}
	name := ask(label)
	if name == "" {
		name = o.PresetName
	}
	if name == "" {
		return "", fmt.Errorf("no engagement name; aborted")
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Authorisation basis:")
	fmt.Fprintln(out, "  1) own infrastructure")
	fmt.Fprintln(out, "  2) client engagement (signed statement of work)")
	fmt.Fprintln(out, "  3) CTF / lab environment")
	basis, ok := map[string]string{
		"1": BasisOwnInfra,
		"2": BasisClient,
		"3": BasisCTFLab,
	}[ask("Choice [1/2/3]: ")]
	if !ok {
		return "", fmt.Errorf("invalid choice; aborted")
	}

	var client, reference string
	if basis == BasisClient {
		client = ask("Client: ")
		reference = ask("Reference of signed order (contract/ticket number): ")
		if reference == "" {
			return "", fmt.Errorf("a client engagement without a reference is not recorded")
		}
	}

	operator := ask("Operator (your name): ")

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Scope. Comma-separated. Domains (subdomains match), IPs or CIDRs.")
	inScope := askList("In scope: ")
	outOfScope := askList("Explicitly out of scope (optional): ")
	var ports []int
	for _, p := range askList("Allowed ports (optional, empty = all): ") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid port %q", p)
		}
		ports = append(ports, n)
	}
	if len(inScope) == 0 {
		return "", fmt.Errorf("empty scope; aborted")
	}

	vulnScanning := false
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Vulnerability scanning (opt-in). By default MOLE is reconnaissance only.")
	fmt.Fprintln(out, "Enabling it adds tools such as nuclei that send probes beyond passive")
	fmt.Fprintln(out, "scanning. Rate limits are enforced in code, and every target is still")
	fmt.Fprintln(out, "checked against the scope gate before execution.")
	if ask("Enable vulnerability scanning tools? (yes/no) [no]: ") == "yes" {
		fmt.Fprintln(out, "I confirm that vulnerability scanning is authorised for the in-scope targets.")
		vulnScanning = ask("Type YES to confirm: ") == "YES"
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "-- Summary --")
	fmt.Fprintf(out, "Engagement : %s\n", name)
	fmt.Fprintf(out, "Basis      : %s\n", basis)
	if client != "" {
		fmt.Fprintf(out, "Client     : %s (ref %s)\n", client, reference)
	}
	fmt.Fprintf(out, "Operator   : %s\n", operator)
	fmt.Fprintf(out, "In scope   : %s\n", strings.Join(inScope, ", "))
	fmt.Fprintf(out, "Out of scope: %s\n", strings.Join(outOfScope, ", "))
	if len(ports) == 0 {
		fmt.Fprintln(out, "Ports      : all")
	} else {
		nums := make([]string, len(ports))
		for i, n := range ports {
			nums[i] = strconv.Itoa(n)
		}
		fmt.Fprintf(out, "Ports      : %s\n", strings.Join(nums, ", "))
	}
	if vulnScanning {
		fmt.Fprintln(out, "Vulnerability scanning : enabled")
	} else {
		fmt.Fprintln(out, "Vulnerability scanning : disabled (reconnaissance only)")
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "I confirm that I am authorised to test the in-scope targets above.")
	if ask("Type YES to confirm: ") != "YES" {
		return "", fmt.Errorf("not confirmed; nothing was written")
	}

	s := ScopeFile{
		Name:         name,
		InScope:      inScope,
		OutOfScope:   outOfScope,
		Ports:        ports,
		VulnScanning: vulnScanning,
		Auth: AuthRecord{
			Basis:     basis,
			Operator:  operator,
			Date:      time.Now().UTC().Format("2006-01-02"),
			Reference: reference,
			Client:    client,
			Confirmed: true,
		},
	}
	dir := filepath.Join(o.Dir, name)
	path := filepath.Join(dir, "scope.yaml")
	if o.Dry {
		fmt.Fprintf(out, "\n(dry-run) scope would be written to %s\n", path)
		return path, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	raw, err := yaml.Marshal(&s)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	fmt.Fprintf(out, "\nScope written to %s\n", path)
	return path, nil
}
