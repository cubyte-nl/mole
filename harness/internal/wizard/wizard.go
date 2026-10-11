// Package wizard implements the interactive startup scoping. It asks targeted
// questions and writes a binding scope.yaml. This is the authorisation step:
// without the confirmation here, nothing runs — not the tools, not the agent.
package wizard

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mole/internal/scope"

	"gopkg.in/yaml.v3"
)

var reader = bufio.NewReader(os.Stdin)

func ask(label string) string {
	fmt.Printf("%s ", label)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func askList(label string) []string {
	raw := ask(label)
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// Run walks the operator through scoping and writes engagement/<name>/scope.yaml.
// It returns the path of the written file.
func Run(engagementDir string) (string, error) {
	fmt.Println("== MOLE scoping ==")
	fmt.Println()
	name := ask("Engagement name: ")
	if name == "" {
		return "", fmt.Errorf("no engagement name; aborted")
	}

	fmt.Println()
	fmt.Println("Authorisation basis:")
	fmt.Println("  1) own infrastructure")
	fmt.Println("  2) client engagement (signed statement of work)")
	fmt.Println("  3) CTF / lab environment")
	basis, ok := map[string]string{
		"1": scope.BasisOwnInfra,
		"2": scope.BasisClient,
		"3": scope.BasisCTFLab,
	}[ask("Choice [1/2/3]: ")]
	if !ok {
		return "", fmt.Errorf("invalid choice; aborted")
	}

	var client, reference string
	if basis == scope.BasisClient {
		client = ask("Client: ")
		reference = ask("Reference of signed order (contract/ticket number): ")
		if reference == "" {
			return "", fmt.Errorf("a client engagement without a reference is not recorded")
		}
	}

	operator := ask("Operator (your name): ")

	fmt.Println()
	fmt.Println("Scope. Comma-separated. Domains (subdomains match), IPs or CIDRs.")
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
	fmt.Println()
	fmt.Println("Vulnerability scanning (opt-in). By default MOLE is reconnaissance only.")
	fmt.Println("Enabling it adds tools such as nuclei that send probes beyond passive")
	fmt.Println("scanning. Rate limits are enforced in code, and every target is still")
	fmt.Println("checked against the scope gate before execution.")
	if ask("Enable vulnerability scanning tools? (yes/no) [no]: ") == "yes" {
		fmt.Println("I confirm that vulnerability scanning is authorised for the in-scope targets.")
		vulnScanning = ask("Type YES to confirm: ") == "YES"
	}

	fmt.Println()
	fmt.Println("-- Summary --")
	fmt.Printf("Engagement : %s\n", name)
	fmt.Printf("Basis      : %s\n", basis)
	if client != "" {
		fmt.Printf("Client     : %s (ref %s)\n", client, reference)
	}
	fmt.Printf("Operator   : %s\n", operator)
	fmt.Printf("In scope   : %s\n", strings.Join(inScope, ", "))
	fmt.Printf("Out of scope: %s\n", strings.Join(outOfScope, ", "))
	if len(ports) == 0 {
		fmt.Println("Ports      : all")
	} else {
		nums := make([]string, len(ports))
		for i, n := range ports {
			nums[i] = strconv.Itoa(n)
		}
		fmt.Printf("Ports      : %s\n", strings.Join(nums, ", "))
	}
	if vulnScanning {
		fmt.Println("Vulnerability scanning : enabled")
	} else {
		fmt.Println("Vulnerability scanning : disabled (reconnaissance only)")
	}
	fmt.Println()
	fmt.Println("I confirm that I am authorised to test the in-scope targets above.")
	if ask("Type YES to confirm: ") != "YES" {
		return "", fmt.Errorf("not confirmed; nothing was written")
	}

	s := scope.Scope{
		Name:         name,
		InScope:      inScope,
		OutOfScope:   outOfScope,
		Ports:        ports,
		VulnScanning: vulnScanning,
		Auth: scope.Authorization{
			Basis:     basis,
			Operator:  operator,
			Date:      time.Now().UTC().Format("2006-01-02"),
			Reference: reference,
			Client:    client,
			Confirmed: true,
		},
	}
	dir := filepath.Join(engagementDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "scope.yaml")
	raw, err := yaml.Marshal(&s)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	fmt.Printf("\nScope written to %s\n", path)
	return path, nil
}
