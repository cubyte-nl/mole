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

	"mole/internal/ledger"
	"mole/internal/scope"
)

// Config controls a single agent run.
type Config struct {
	MaxSteps  int
	Objective string
	ReportDir string
	// Ledger is the engagement's findings working memory; when set, its state
	// is re-injected into the model's context every step, and its finding →
	// exploitation chain is rendered into the report. Nil disables the ledger.
	Ledger *ledger.Ledger
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
	startMeta := map[string]any{"engagement": s.Name, "vulnerability_scanning": s.VulnScanning}
	if cfg.Ledger != nil {
		startMeta["ledger"] = cfg.Ledger.Path()
	}
	return coreagent.Run[*scope.Scope](ctx, s, client, reg, coreagent.Config[*scope.Scope]{
		MaxSteps:  cfg.MaxSteps,
		Objective: objective,
		ReportDir: cfg.ReportDir,
		Out:       cfg.Out,
		// The ledger's compact state is re-injected before every chat call,
		// so early recon results never fall out of the model's salience.
		RenderTurnState: func(turn, steps int) string {
			if cfg.Ledger == nil {
				return ""
			}
			return cfg.Ledger.Render(steps)
		},
		SystemPrompt: func(s *scope.Scope, objective, model string) string {
			return systemPrompt(s, objective, model)
		},
		RenderReport: func(obj *scope.Scope, objective, final string, steps int, transcript string) string {
			return renderReport(obj, cfg.Ledger, objective, final, steps, transcript)
		},
		RenderHeader: func(step int, tool, args string) string { return "→ " + tool + "(" + args + ")" },
		RenderResult: actionResult,
		StartMeta:    startMeta,
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
	b.WriteString("- Light scripting: the shell tool runs small bash/python3 scripts locally in the\n")
	b.WriteString("  harness (not on the target). Use it to adapt a technique when stock commands\n")
	b.WriteString("  don't fit — patch a public exploit's hardcoded values, carry a session across\n")
	b.WriteString("  requests, parse output, loop a probe over in-scope hosts. Scripts may reach the\n")
	b.WriteString("  network only toward in-scope targets; keep them minimal and non-destructive.\n")
	b.WriteString("  The full script is the command argument and is recorded verbatim in the\n")
	b.WriteString("  transcript — cite it in record_finding when it produces a result.\n")
	if s.VulnScanning {
		b.WriteString("- Vulnerability scanning is enabled for this engagement: you may use the\n")
		b.WriteString("  vulnerability-scanning tools (nuclei) and rate-limited directory fuzzing\n")
		b.WriteString("  (ffuf, web targets only) on in-scope targets. Their rate limits are\n")
		b.WriteString("  enforced in code. Validate with the minimum needed and stop once a\n")
		b.WriteString("  finding is confirmed.\n")
		b.WriteString("- No denial of service, no data exfiltration, no changes to the systems you\n")
		b.WriteString("  test — the one controlled exception is the post-foothold work below.\n")
		b.WriteString("- Public exploits: when a public exploit or technique (nuclei template, CVE\n")
		b.WriteString("  write-up, exploit-db snippet) does not fit the target as-is, do not give up —\n")
		b.WriteString("  adapt it with a small script through the shell tool (patch the hardcoded\n")
		b.WriteString("  URL/path/payload, add the session it needs), then validate the adapted form\n")
		b.WriteString("  on the in-scope target and record it with the script as evidence.\n")
		b.WriteString("- Web bugs (SQL injection, XSS, file inclusion/upload, command injection,\n")
		b.WriteString("  IDOR): enumerate the application's inputs first (http_probe the pages, read\n")
		b.WriteString("  the forms), then validate each input with web_check — it fires fixed,\n")
		b.WriteString("  non-destructive payloads (the tool, not you, picks them) and returns a\n")
		b.WriteString("  verdict with evidence. Use http_request only for crafted probes you have\n")
		b.WriteString("  judged safe (POST forms, custom headers). Record each verdict with\n")
		b.WriteString("  record_finding, citing the evidence lines.\n")
		b.WriteString("- Post-foothold: once command execution lands on an in-scope target (e.g.\n")
		b.WriteString("  through a confirmed command-injection input), register the vector with the\n")
		b.WriteString("  exec tool (url, method, param, separator, optional value and headers; it\n")
		b.WriteString("  verifies with 'id' and records the foothold in the ledger). Then work\n")
		b.WriteString("  through the privilege-escalation checklist from knowledge_search, one\n")
		b.WriteString("  minimal, non-destructive command at a time (Linux: sudo, SUID, cron;\n")
		b.WriteString("  Windows: tokens, stored credentials). Stop at the first successful\n")
		b.WriteString("  escalation; record each step with record_finding, citing its output as\n")
		b.WriteString("  evidence.\n")
	} else {
		b.WriteString("- Reconnaissance only: DNS, port scanning, service detection, HTTP probes. No\n")
		b.WriteString("  exploitation, no fuzzing, no denial of service, no data exfiltration, no changes\n")
		b.WriteString("  to the systems you test.\n")
	}
	// Pointer to the technique knowledge (embedded, served by the
	// knowledge_search tool): per-service enumeration checklists and the
	// light-scripting guide for every engagement, plus the post-foothold
	// playbook when exploitation is in scope. It never overrides the scope
	// gate or the rules above.
	b.WriteString("- Technique knowledge: the knowledge_search tool holds the per-service enumeration\n")
	b.WriteString("  checklists (web/HTTP, SSH, RDP, databases, Samba, SMTP), the light-scripting\n")
	b.WriteString("  guide (adapting a public exploit into a small bash/python3 script: when to\n")
	b.WriteString("  adapt, bash and python patterns, safety, keeping the script auditable), and,\n")
	b.WriteString("  when vulnerability scanning is enabled, the core web-bug playbook (SQLi, XSS,\n")
	b.WriteString("  file inclusion/upload, command injection, IDOR: what to look for, minimal\n")
	b.WriteString("  payloads, safe validation) plus the privilege-escalation checklist (Linux\n")
	b.WriteString("  sudo/SUID/cron, Windows tokens and stored credentials); when exploitation is in\n")
	b.WriteString("  scope it also holds the Linux & Windows post-foothold playbook (first minutes\n")
	b.WriteString("  after a foothold, CLI, permissions, services, cron, credentials, lateral\n")
	b.WriteString("  movement).\n")
	b.WriteString("  Search it with a specific query — 'web enumeration', 'sql injection validation',\n")
	b.WriteString("  'lfi payloads', 'ssh service', 'sudo escalation', 'token abuse', 'adapt exploit\n")
	b.WriteString("  with a script', 'python requests session' — when a service is discovered, a\n")
	b.WriteString("  public technique needs adapting, or a foothold lands, and act on the sections it\n")
	b.WriteString("  returns. Record the foothold and every vector you enumerate with\n")
	b.WriteString("  record_finding, citing evidence.\n")
	b.WriteString("- Work systematically: resolve names, scan, then probe what the scan reveals.\n")
	b.WriteString("- Exhaust enumeration per service: for each service you discover, run at least one\n")
	b.WriteString("  service-specific check (the checklists tell you which). Stop enumerating a\n")
	b.WriteString("  service only with a documented reason — recorded in the report (e.g. the port\n")
	b.WriteString("  closed, the check returned nothing after the wordlist cap was hit).\n")
	b.WriteString("- Quote observed output as evidence for every finding.\n")
	b.WriteString("- Record every significant finding with record_finding as you make it, and when you act on a\n")
	b.WriteString("  finding update it with update_finding (investigated, exploited, or dropped with a reason).\n")
	b.WriteString("  The ledger is re-shown to you every step; leave no finding 'new' in the final report.\n")
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

func renderReport(s *scope.Scope, led *ledger.Ledger, objective, final string, steps int, transcript string) string {
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
	// The structured finding → exploitation chain, rendered from the ledger
	// rather than from the model's prose alone.
	if led != nil {
		if chain := led.RenderReport(); chain != "" {
			b.WriteString("\n" + chain)
		}
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
