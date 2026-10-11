// Package scope is the scope gate: the hard boundary inside which MOLE may
// operate. Every tool asks the gate before it touches a target. Out-of-scope
// targets are refused, and the gate fails closed: on any doubt (e.g. a name
// that will not resolve) the answer is no. This is not a UX layer; it is what
// makes MOLE an authorised-testing harness rather than a tool that can be
// pointed at arbitrary endpoints.
package scope

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Authorisation bases.
const (
	BasisOwnInfra = "own-infra"
	BasisClient   = "client-engagement"
	BasisCTFLab   = "ctf-lab"
)

// Authorization is the recorded authorisation basis, stamped on every report.
type Authorization struct {
	Basis     string `yaml:"basis"`
	Operator  string `yaml:"operator"`
	Date      string `yaml:"date"`
	Reference string `yaml:"reference,omitempty"` // contract/ticket number for client engagements
	Client    string `yaml:"client,omitempty"`
	Confirmed bool   `yaml:"confirmed"`
}

// Scope is the recorded, binding scope of an engagement.
type Scope struct {
	Name         string        `yaml:"name"`
	InScope      []string      `yaml:"in_scope"`
	OutOfScope   []string      `yaml:"out_of_scope,omitempty"`
	Ports        []int         `yaml:"ports,omitempty"`         // empty = all ports within scope
	VulnScanning bool          `yaml:"vuln_scanning,omitempty"` // opt-in: vulnerability scanning tools
	Auth         Authorization `yaml:"authorisation"`

	// Exclusions are the runtime addendum: targets the agent judged out of
	// scope during a run and the gate was asked to enforce. They only
	// narrow scope and live in the sidecar exclusions.yaml (ExclusionsPath),
	// never in the scope file itself, which stays the operator's
	// authorisation record.
	Exclusions     []Exclusion `yaml:"-"`
	ExclusionsPath string      `yaml:"-"`

	resolver *net.Resolver // nil = system resolver
}

// Validate checks that the scope is confirmed and non-empty.
func (s *Scope) Validate() error {
	if s.Auth == (Authorization{}) || !s.Auth.Confirmed {
		return fmt.Errorf("scope not confirmed; run 'mole init' and confirm the authorisation first")
	}
	if len(s.InScope) == 0 {
		return fmt.Errorf("empty in-scope list: no target is allowed")
	}
	return nil
}

// Load reads and validates a scope file.
func Load(path string) (*Scope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scope
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	// Backward compatibility: earlier releases named the opt-in "exploit".
	// Honor that key so a recorded opt-in is never silently dropped.
	var legacy struct {
		Exploit bool `yaml:"exploit"`
	}
	if err := yaml.Unmarshal(raw, &legacy); err == nil && legacy.Exploit {
		s.VulnScanning = true
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// CheckTarget reports whether host (optionally on port) is allowed. It
// returns (allowed, reason) and fails closed on any doubt.
func (s *Scope) CheckTarget(ctx context.Context, host string, port *int) (bool, string) {
	host = StripHost(host)
	addrs, err := s.Resolve(ctx, host)
	if err != nil {
		return false, fmt.Sprintf("cannot resolve %s (%v); denied", host, err)
	}
	out := s.effectiveOutOfScope()
	if matchName(host, out) {
		return false, fmt.Sprintf("%s is explicitly out of scope", host)
	}
	for _, a := range addrs {
		if matchAddr(a, out) {
			return false, fmt.Sprintf("%s resolves to %s, which is out of scope", host, a)
		}
	}
	allowed := matchName(host, s.InScope)
	if !allowed {
		for _, a := range addrs {
			if matchAddr(a, s.InScope) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return false, fmt.Sprintf("%s is not in the in-scope list", host)
	}
	if port != nil && len(s.Ports) > 0 && !containsInt(s.Ports, *port) {
		return false, fmt.Sprintf("port %d is not in the allowed ports", *port)
	}
	return true, "in scope"
}

// NameInScope reports whether a host name matches the recorded in-scope name
// patterns (suffix match). It is used by tools that derive candidate names
// (e.g. subdomain discovery) and want a belt-and-braces scope check.
func (s *Scope) NameInScope(name string) bool {
	return matchName(name, s.InScope)
}

// Resolve maps a host name to its addresses; a bare IP resolves to itself.
func (s *Scope) Resolve(ctx context.Context, host string) ([]string, error) {
	if _, err := netip.ParseAddr(host); err == nil {
		return []string{host}, nil
	}
	r := s.resolver
	if r == nil {
		r = net.DefaultResolver
	}
	raw, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, a := range raw {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

// AuthHeader renders the authorisation block stamped on every report.
func (s *Scope) AuthHeader() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Engagement : %s\n", s.Name)
	fmt.Fprintf(&b, "Basis      : %s\n", s.Auth.Basis)
	fmt.Fprintf(&b, "Operator   : %s\n", s.Auth.Operator)
	fmt.Fprintf(&b, "Date       : %s\n", s.Auth.Date)
	if s.Auth.Reference != "" {
		fmt.Fprintf(&b, "Reference  : %s\n", s.Auth.Reference)
	}
	if s.Auth.Client != "" {
		fmt.Fprintf(&b, "Client     : %s\n", s.Auth.Client)
	}
	return strings.TrimRight(b.String(), "\n")
}

// Describe renders the scope for prompts and the CLI.
func (s *Scope) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Engagement   : %s\n", s.Name)
	fmt.Fprintf(&b, "In scope     : %s\n", joinOr(s.InScope, "-"))
	fmt.Fprintf(&b, "Out of scope : %s\n", joinOr(s.OutOfScope, "-"))
	if len(s.Exclusions) > 0 {
		targets := make([]string, len(s.Exclusions))
		for i, e := range s.Exclusions {
			targets[i] = e.Target
		}
		b.WriteString("Exclusions   : " + strings.Join(targets, ", ") + " (runtime addendum)\n")
	}
	if len(s.Ports) == 0 {
		b.WriteString("Ports        : all\n")
	} else {
		b.WriteString("Ports        : " + joinInts(s.Ports) + "\n")
	}
	if s.VulnScanning {
		b.WriteString("Vulnerability scanning : enabled\n")
	} else {
		b.WriteString("Vulnerability scanning : disabled (reconnaissance only)\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// StripHost reduces a URL, host:port or bare host to a bare host.
func StripHost(u string) string {
	for _, p := range []string{"https://", "http://"} {
		if strings.HasPrefix(u, p) {
			u = strings.TrimPrefix(u, p)
		}
	}
	u = strings.SplitN(u, "/", 2)[0]
	u = strings.SplitN(u, ":", 2)[0]
	return strings.TrimSpace(u)
}

func matchName(host string, patterns []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, p := range patterns {
		p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if strings.Contains(p, "/") {
			continue // CIDRs are not name patterns
		}
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

func matchAddr(addr string, patterns []string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if strings.Contains(p, "/") {
			if n, err := netip.ParsePrefix(p); err == nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if t, err := netip.ParseAddr(p); err == nil && t == ip {
			return true
		}
	}
	return false
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func joinOr(xs []string, empty string) string {
	if len(xs) == 0 {
		return empty
	}
	return strings.Join(xs, ", ")
}

func joinInts(xs []int) string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Itoa(x)
	}
	return strings.Join(out, ", ")
}
