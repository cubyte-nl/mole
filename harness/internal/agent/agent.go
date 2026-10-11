// Package agent wires MOLE's domain into the shared core loop
// (github.com/cubyte-nl/agent-core/agent). The control flow — chat, tool
// dispatch, the step budget, the transcript, retries and truncated-response
// handling — lives in the core. This package supplies the MOLE-specific
// pieces: the system prompt (reconnaissance vs vulnerability scanning), the
// live action log, and the report body.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	coreagent "github.com/cubyte-nl/agent-core/agent"
	"github.com/cubyte-nl/agent-core/llm"
	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// Config controls a single agent run.
type Config struct {
	MaxSteps  int
	Objective string
	ReportDir string
	// Out receives the live transcript; nil disables printing.
	Out func(line string)
}

// RunResult is the outcome of an agent run.
type RunResult = coreagent.RunResult

// Run executes the agent loop against the shared core, injecting MOLE's
// prompt, action log and report, and writes the final report into cfg.ReportDir.
func Run(ctx context.Context, s *scope.Scope, client *llm.Client, reg *core.Registry[*scope.Scope], cfg Config) (*RunResult, error) {
	objective := cfg.Objective
	if objective == "" {
		objective = "Perform initial reconnaissance of the in-scope targets and report what you find."
	}
	return coreagent.Run[*scope.Scope](ctx, s, client, reg, coreagent.Config[*scope.Scope]{
		MaxSteps:     cfg.MaxSteps,
		Objective:    objective,
		ReportDir:    cfg.ReportDir,
		Out:          cfg.Out,
		SystemPrompt: systemPrompt,
		RenderReport: renderReport,
		RenderHeader: func(step int, tool, args string) string { return "→ " + tool + "(" + args + ")" },
		RenderResult: actionResult,
		StartMeta:    map[string]any{"engagement": s.Name, "vulnerability_scanning": s.VulnScanning},
	})
}

func systemPrompt(s *scope.Scope, objective, model string) string {
	var b strings.Builder
	b.WriteString("You are MOLE, an authorised security reconnaissance agent. A human operator\n")
	b.WriteString("started you for this engagement; you plan and execute the reconnaissance, and\n")
	b.WriteString("you are bound by the scope below.\n\n")
	b.WriteString("## Authorisation\n")
	b.WriteString(s.AuthHeader())
	b.WriteString("\n\n## Scope\n")
	b.WriteString(s.Describe())
	b.WriteString("\n\n## Objective\n")
	b.WriteString(objective)
	b.WriteString("\n\n## Rules\n")
	b.WriteString("- Operate only on targets in scope. The scope gate is authoritative: when a tool\n")
	b.WriteString("  call is denied, that target is off-limits. Do not reword the target (alias, IP\n")
	b.WriteString("  instead of name, subdomain trickery) to work around a denial.\n")
	b.WriteString("- If you judge a discovered target to be out of scope (e.g. infrastructure you\n")
	b.WriteString("  did not authorise), call note_out_of_scope with a reason before probing it —\n")
	b.WriteString("  and do not probe it at all. Exclusions only narrow scope; they persist across\n")
	b.WriteString("  runs, and the gate refuses to record targets that are not in scope.\n")
	if s.VulnScanning {
		b.WriteString("- Vulnerability scanning is enabled for this engagement: you may use the\n")
		b.WriteString("  vulnerability-scanning tools (nuclei) on in-scope targets. Their rate limits\n")
		b.WriteString("  are enforced in code. Still: no fuzzing, no denial of service, no data\n")
		b.WriteString("  exfiltration, no changes to the systems you test. Validate with the minimum\n")
		b.WriteString("  needed and stop once a finding is confirmed.\n")
	} else {
		b.WriteString("- Reconnaissance only: DNS, port scanning, service detection, HTTP probes. No\n")
		b.WriteString("  exploitation, no fuzzing, no denial of service, no data exfiltration, no changes\n")
		b.WriteString("  to the systems you test.\n")
	}
	b.WriteString("- Work systematically: resolve names, scan, then probe what the scan reveals.\n")
	b.WriteString("- Quote observed output as evidence for every finding.\n")
	sections := "Summary, Targets, Findings, Recommendations"
	if s.VulnScanning {
		sections = "Summary, Targets, Findings, Vulnerability scanning, Recommendations"
	}
	b.WriteString("- When you have enough evidence, stop calling tools and write your final report\n")
	b.WriteString("  as markdown with the sections: " + sections + ".\n")
	if model != "" {
		b.WriteString("\n(You are running as model " + model + ".)\n")
	}
	return b.String()
}

func renderReport(s *scope.Scope, objective, final string, steps int, transcript string) string {
	var b strings.Builder
	b.WriteString("# Reconnaissance report — " + s.Name + "\n\n")
	b.WriteString("## Authorisation\n\n")
	b.WriteString(s.AuthHeader())
	b.WriteString("\n\n## Scope\n\n")
	b.WriteString(s.Describe())
	b.WriteString("\n\n## Objective\n\n")
	b.WriteString(objective + "\n\n")
	b.WriteString("## Findings\n\n")
	if strings.TrimSpace(final) == "" {
		b.WriteString("_The agent produced no final report._\n")
	} else {
		b.WriteString(final + "\n")
	}
	fmt.Fprintf(&b, "\n---\nGenerated by MOLE (LLM-driven) on %s after %d tool step(s).\n",
		time.Now().Format(time.RFC3339), steps)
	if transcript != "" {
		b.WriteString("Transcript: " + transcript + "\n")
	}
	return b.String()
}

// actionResult renders the live action-log lines for a tool result: the gate
// verdict, or the structured result JSON (truncated).
func actionResult(res core.Result) []string {
	if !res.Allowed {
		return []string{"← DENIED: " + res.Reason}
	}
	if res.Reason != "" {
		return []string{"← " + res.Tool + ": " + res.Reason}
	}
	raw, _ := json.Marshal(res)
	s := string(raw)
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return []string{"← " + s}
}
