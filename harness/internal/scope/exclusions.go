package scope

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Exclusion is a single runtime exclusion recorded in the exclusions sidecar:
// a target the agent judged out of scope and asked the gate to enforce.
// Exclusions only narrow scope; they can never widen it.
type Exclusion struct {
	Target string `yaml:"target"`
	Reason string `yaml:"reason"`
	At     string `yaml:"at"`     // RFC3339 UTC
	Source string `yaml:"source"` // "agent" | "operator"
}

// LoadExclusions points the scope at the sidecar exclusions.yaml and loads
// it. A missing file is fine: it means the agent has not excluded anything
// yet.
func (s *Scope) LoadExclusions(path string) error {
	s.ExclusionsPath = path
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("scope: reading exclusions: %w", err)
	}
	var xs []Exclusion
	if err := yaml.Unmarshal(raw, &xs); err != nil {
		return fmt.Errorf("scope: parsing exclusions %s: %w", path, err)
	}
	s.Exclusions = xs
	return nil
}

// Exclude records a runtime exclusion: a target the agent judged out of
// scope (e.g. infrastructure it did not authorise). Exclusions only narrow
// scope — they can never widen it. Guards:
//
//   - target must be non-empty and a single host or IP (no CIDR)
//   - duplicate targets are a no-op
//   - target must fall under a recorded in-scope pattern (checked without
//     DNS, against the raw pattern), so the addendum cannot be used to
//     "exclude" a target that was never in scope
//   - a sidecar must be configured (LoadExclusions), otherwise the agent
//     has no authority to modify scope
//
// On success the exclusion is persisted to the sidecar, so the gate
// enforces it on every subsequent run, not just the one that recorded it.
func (s *Scope) Exclude(target, reason string) error {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return errors.New("scope: exclusion target is empty")
	}
	// CIDR check on the raw input: StripHost would eat the /prefix.
	if strings.Contains(raw, "/") {
		return fmt.Errorf("scope: exclusion %q: CIDR ranges are not allowed in exclusions", raw)
	}
	target = strings.TrimSpace(StripHost(target))
	if target == "" {
		return errors.New("scope: exclusion target is empty")
	}
	for _, e := range s.Exclusions {
		if strings.EqualFold(e.Target, target) {
			return nil // idempotent
		}
	}
	if !s.isNarrowable(target) {
		return fmt.Errorf("scope: %q is not in the recorded in-scope list; exclusions may only narrow, not widen", target)
	}
	if s.ExclusionsPath == "" {
		// A scope loaded without a sidecar is read-only: the agent has no
		// authority to modify it.
		return errors.New("scope: no exclusions sidecar configured; the agent cannot modify scope")
	}
	s.Exclusions = append(s.Exclusions, Exclusion{
		Target: target,
		Reason: strings.TrimSpace(reason),
		At:     time.Now().UTC().Format(time.RFC3339),
		Source: "agent",
	})
	if err := s.persistExclusions(); err != nil {
		s.Exclusions = s.Exclusions[:len(s.Exclusions)-1]
		return err
	}
	return nil
}

// isNarrowable reports whether target falls under at least one recorded
// in-scope pattern, checked without DNS (raw name-suffix and IP/CIDR
// matching). This is what makes Exclude a pure narrowing operation: if the
// target is not provably in scope, it cannot be excluded.
func (s *Scope) isNarrowable(target string) bool {
	return matchName(target, s.InScope) || matchAddr(target, s.InScope)
}

// effectiveOutOfScope is the union of the operator's out_of_scope list and
// the runtime exclusion targets.
func (s *Scope) effectiveOutOfScope() []string {
	seen := make(map[string]bool, len(s.OutOfScope)+len(s.Exclusions))
	out := make([]string, 0, len(s.OutOfScope)+len(s.Exclusions))
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, p := range s.OutOfScope {
		add(p)
	}
	for _, e := range s.Exclusions {
		add(e.Target)
	}
	return out
}

// persistExclusions rewrites the whole sidecar, including the header
// comment.
func (s *Scope) persistExclusions() error {
	data, err := yaml.Marshal(s.Exclusions)
	if err != nil {
		return fmt.Errorf("scope: serialising exclusions: %w", err)
	}
	raw := append([]byte(exclusionsHeader), data...)
	if err := os.WriteFile(s.ExclusionsPath, raw, 0o644); err != nil {
		return fmt.Errorf("scope: writing exclusions: %w", err)
	}
	return nil
}

const exclusionsHeader = `# exclusions.yaml — runtime scope exclusions for this engagement.
# Written by MOLE (the note_out_of_scope tool) and never by the scope
# wizard. Entries only narrow scope: they can never widen it and never
# modify scope.yaml, which stays the operator's authorisation record.
`
