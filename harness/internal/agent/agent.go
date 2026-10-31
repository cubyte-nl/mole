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
		b.WriteString("- Web bugs: enumerate the application's inputs first (http_probe the pages,\n")
		b.WriteString("  read the forms), then validate each. The fixed-payload classes — SQL\n")
		b.WriteString("  injection, reflected XSS, file inclusion/upload, command injection, IDOR —\n")
		b.WriteString("  go through web_check: it fires non-destructive payloads (the tool, not you,\n")
		b.WriteString("  picks them) and returns a verdict with evidence. The stateful classes —\n")
		b.WriteString("  blind SQLi, stored/DOM XSS, CSRF, authorisation bypass, open redirect, weak\n")
		b.WriteString("  session IDs, brute-force resistance, CAPTCHA/CSP — go through http_request\n")
		b.WriteString("  (follow_redirects off for open-redirect checks) and a small shell script\n")
		b.WriteString("  where a session, token, or timing measurement matters; the playbook in\n")
		b.WriteString("  knowledge_search gives each one's minimal, safe shape. Judge every probe\n")
		b.WriteString("  safe before firing it. Record each verdict with record_finding, citing the\n")
		b.WriteString("  evidence lines.\n")
		b.WriteString("- Post-foothold: once command execution lands on an in-scope target (e.g.\n")
		b.WriteString("  through a confirmed command-injection input), register the vector with the\n")
		b.WriteString("  exec tool (url, method, param, separator, optional value and headers; it\n")
		b.WriteString("  verifies with 'id' and records the foothold in the ledger). Then work\n")
		b.WriteString("  through the privilege-escalation checklist from knowledge_search, one\n")
		b.WriteString("  minimal, non-destructive command at a time (Linux: sudo, SUID, cron, container\n")
		b.WriteString("  escape; Windows: tokens, stored credentials). Stop at the first successful\n")
		b.WriteString("  escalation; record each step with record_finding, citing its output as\n")
		b.WriteString("  evidence — a negative conclusion (no path found) is a finding too: record\n")
		b.WriteString("  it with the outputs that closed each branch.\n")
		b.WriteString("- Exploitation toolset: payload generates msfvenom payloads (e.g. reverse\n")
		b.WriteString("  shells) aimed at in-scope targets; netcat arms a local listener to receive\n")
		b.WriteString("  them — arm it BEFORE firing the payload, and use the lhost and port it\n")
		b.WriteString("  returns as LHOST/LPORT — and a later collect returns what arrived; crack\n")
		b.WriteString("  attacks hashes captured during the run offline against the bundled wordlist\n")
		b.WriteString("  (pass the in-scope host the hash came from as 'source'). All three are\n")
		b.WriteString("  scope-gated and bounded in code (timeouts, output caps).\n")
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
	b.WriteString("  when vulnerability scanning is enabled, the core web-bug playbook (SQL\n")
	b.WriteString("  injection including blind and impact assessment — schema scope, file\n")
	b.WriteString("  read/write — reflected/stored/DOM XSS, file inclusion/upload, command\n")
	b.WriteString("  injection, IDOR, CSRF, authorisation bypass, open redirect, weak session\n")
	b.WriteString("  IDs, brute-force resistance, credential reuse, CAPTCHA/CSP, setup/install\n")
	b.WriteString("  endpoints: what to look for, minimal payloads, safe validation, fix\n")
	b.WriteString("  direction) plus the privilege-escalation checklist (Linux sudo/SUID/cron/\n")
	b.WriteString("  container escape, Windows tokens and stored credentials); when exploitation is\n")
	b.WriteString("  in scope it also holds the Linux & Windows post-foothold playbook (first\n")
	b.WriteString("  minutes after a foothold, CLI, permissions, services, cron, credentials,\n")
	b.WriteString("  lateral movement and adjacent hosts) and the harness toolset guide (payload +\n")
	b.WriteString("  netcat reverse shells, offline cracking with crack).\n")
	b.WriteString("  Search it with a specific query — 'web enumeration', 'sql injection validation',\n")
	b.WriteString("  'sqli file access', 'credential reuse', 'setup endpoint', 'lfi payloads',\n")
	b.WriteString("  'ssh service', 'sudo escalation', 'token abuse', 'container escape',\n")
	b.WriteString("  'adjacent host out of scope', 'adapt exploit with a script', 'python requests\n")
	b.WriteString("  session' — when a service is discovered, a public technique needs adapting, or\n")
	b.WriteString("  a foothold lands, and act on the sections it returns. Record the foothold and\n")
	b.WriteString("  every vector you enumerate with record_finding, citing evidence.\n")
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
