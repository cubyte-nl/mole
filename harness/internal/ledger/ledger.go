// persistent list of the findings an engagement has produced, each carrying
// its source (the probe that found it), evidence, lifecycle status, and the
// exploitation link when one acted on it.
//
// The ledger is what makes recon → exploitation read as one continuous plan.
// A finding lives only in the model's context memory until it is recorded; once
// recorded it is re-injected into the model's context on every turn, so early
// recon results never fall out of salience, every action can cite the finding
// that motivated it, and the report can render the finding → exploitation chain
// from structured data rather than from prose alone.
package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Status is the lifecycle state of a finding.
type Status string

const (
	StatusNew          Status = "new"
	StatusInvestigated Status = "investigated"
	StatusExploited    Status = "exploited"
	StatusDropped      Status = "dropped"
)

// Finding is one recorded observation.
type Finding struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Target   string `json:"target,omitempty"`
	Source   string `json:"source,omitempty"`   // the probe that found it, e.g. "nmap 144.76.67.91"
	Evidence string `json:"evidence,omitempty"` // short quoted observation
	Status   Status `json:"status"`
	Exploit  string `json:"exploit,omitempty"` // what acted on it and the outcome
	Note     string `json:"note,omitempty"`
}

// Ledger is the persistent findings store for one engagement run.
type Ledger struct {
	mu       sync.Mutex
	path     string
	findings []Finding
	nextID   int
}

// New opens the ledger at path, loading any findings already recorded (a
// resumed engagement keeps its working memory) or starting empty.
func New(path string) (*Ledger, error) {
	l := &Ledger{path: path, nextID: 1}
	if raw, err := os.ReadFile(path); err == nil {
		var data struct {
			Findings []Finding `json:"findings"`
			NextID   int       `json:"next_id"`
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			return nil, fmt.Errorf("ledger: reading %s: %w", path, err)
		}
		l.findings = data.Findings
		l.nextID = data.NextID
		for _, f := range l.findings {
			if n := f.idNum(); n+1 > l.nextID {
				l.nextID = n + 1
			}
		}
	}
	return l, nil
}

// Path is the ledger file, for the report and transcript.
func (l *Ledger) Path() string { return l.path }

// Record appends a new finding (status new) and returns it.
func (l *Ledger) Record(summary, target, source, evidence string) (*Finding, error) {
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return nil, fmt.Errorf("ledger: summary is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f := &Finding{
		ID:       fmt.Sprintf("F%d", l.nextID),
		Summary:  summary,
		Target:   strings.TrimSpace(target),
		Source:   strings.TrimSpace(source),
		Evidence: strings.TrimSpace(evidence),
		Status:   StatusNew,
	}
	l.nextID++
	l.findings = append(l.findings, *f)
	if err := l.save(); err != nil {
		return nil, err
	}
	return f, nil
}

// ParseStatus reports whether s is a known finding status.
func ParseStatus(s string) (Status, bool) {
	switch st := Status(strings.TrimSpace(s)); st {
	case StatusNew, StatusInvestigated, StatusExploited, StatusDropped:
		return st, true
	}
	return "", false
}

// Update sets the lifecycle fields of an existing finding by id (e.g. "F3")
// and returns the updated finding. An unknown status is an error.
func (l *Ledger) Update(id, status, exploit, note string) (*Finding, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	if st := strings.TrimSpace(status); st != "" {
		if _, ok := ParseStatus(st); !ok {
			return nil, fmt.Errorf("ledger: unknown status %q (want new, investigated, exploited, dropped)", st)
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.findings {
		if strings.EqualFold(l.findings[i].ID, id) {
			if st := Status(strings.TrimSpace(status)); st != "" {
				l.findings[i].Status = st
			}
			if e := strings.TrimSpace(exploit); e != "" {
				l.findings[i].Exploit = e
			}
			if n := strings.TrimSpace(note); n != "" {
				l.findings[i].Note = n
			}
			f := l.findings[i]
			if err := l.save(); err != nil {
				return nil, err
			}
			return &f, nil
		}
	}
	return nil, fmt.Errorf("ledger: no finding %q", id)
}

// Findings returns a snapshot of the findings in order.
func (l *Ledger) Findings() []Finding {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Finding, len(l.findings))
	copy(out, l.findings)
	return out
}

// Empty reports whether no finding has been recorded.
func (l *Ledger) Empty() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.findings) == 0
}

// Render produces the compact state block injected into the model's context on
// every turn: one line per finding, and the set still awaiting follow-up.
func (l *Ledger) Render(steps int) string {
	fs := l.Findings()
	if len(fs) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## Findings ledger (step %d)\n", steps)
	b.WriteString("Record each significant finding as you go; act on them and update their status.\n")
	for _, f := range fs {
		line := fmt.Sprintf("%s [%s] %s", f.ID, f.Status, f.Summary)
		if f.Target != "" {
			line += " — " + f.Target
		}
		if f.Source != "" {
			line += " (src: " + f.Source + ")"
		}
		if f.Status == StatusExploited && f.Exploit != "" {
			line += " → " + f.Exploit
		}
		if f.Status == StatusDropped && f.Note != "" {
			line += " (" + f.Note + ")"
		}
		b.WriteString(line + "\n")
	}
	var open []string
	for _, f := range fs {
		if f.Status == StatusNew {
			open = append(open, f.ID)
		}
	}
	if len(open) > 0 {
		b.WriteString("\nAwaiting follow-up: " + strings.Join(open, ", ") +
			" — investigate, exploit, or drop each before the final report.\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// RenderReport renders the finding → exploitation chain for the report: one row
// per finding, with the probe that found it and the action/outcome when it was
// exploited.
func (l *Ledger) RenderReport() string {
	fs := l.Findings()
	if len(fs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Finding → exploitation chain\n\n")
	b.WriteString("| # | Finding | Found via | Status | Action / outcome |\n")
	b.WriteString("|---|---------|-----------|--------|------------------|\n")
	for _, f := range fs {
		src := f.Source
		if src == "" {
			src = "—"
		}
		chain := "—"
		switch {
		case f.Status == StatusExploited && f.Exploit != "":
			chain = f.Exploit
		case f.Status == StatusDropped && f.Note != "":
			chain = "dropped: " + f.Note
		case f.Status == StatusInvestigated:
			chain = "investigated, no further action"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			f.ID, f.Summary, src, f.Status, chain))
	}
	return b.String()
}

func (l *Ledger) save() error {
	if l.path == "" {
		return nil
	}
	data := struct {
		Findings []Finding `json:"findings"`
		NextID   int       `json:"next_id"`
	}{Findings: l.findings, NextID: l.nextID}
	if l.findings == nil {
		data.Findings = []Finding{}
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

func (f Finding) idNum() int {
	n := 0
	for _, c := range f.ID {
		if c < '0' || c > '9' {
			continue
		}
		n = n*10 + int(c-'0')
	}
	return n
}
