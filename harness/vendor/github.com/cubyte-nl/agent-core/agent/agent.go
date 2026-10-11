// Package agent runs the shared LLM-driven loop: the model plans the work,
// calls the gated tools, reads the results, and finishes with a report. The
// model never bypasses the boundary; every tool call is checked before
// execution, and denials are fed back as tool results. When a confirmation is
// required, each mutating call is put to the operator before it runs.
//
// The loop is generic over the agent's boundary type B and owns only the
// control flow — chat, tool dispatch, the operator-confirmation step, the step
// budget with a forced final report, the transcript, retries, and truncated-
// response handling. Everything domain-specific (the system prompt text, the
// live action-log rendering, the report body, the transcript's start metadata)
// is injected through Config.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cubyte-nl/agent-core/llm"
	"github.com/cubyte-nl/agent-core/tools"
)

// Config controls a single agent run over boundary type B.
type Config[B tools.Boundary] struct {
	MaxSteps  int
	Objective string
	ReportDir string
	// Out receives the live action log; nil disables printing.
	Out func(line string)
	// ProgressInterval is how often a heartbeat line is emitted while a tool is
	// still running, so a slow action (nmap, nuclei) shows it is alive. Unset
	// defaults to 15s; a negative value disables the heartbeat.
	ProgressInterval time.Duration
	// MaxToolResult caps, in bytes, how much of a tool result is fed back to the
	// model, so one large result (nmap, nuclei) cannot overflow the context
	// window. The full result is always kept in the transcript; only the model's
	// copy is capped. Unset defaults to 8 KiB; a negative value feeds it uncapped.
	MaxToolResult int

	// SystemPrompt builds the system prompt from the boundary, objective and
	// model. Required.
	SystemPrompt func(b B, objective, model string) string
	// RenderReport builds the final markdown report body. Required.
	RenderReport func(b B, objective, final string, steps int, transcript string) string
	// RenderHeader renders the live action-log header shown before a tool runs.
	// Defaults to a compact "[step] tool(args)" line.
	RenderHeader func(step int, tool, args string) string
	// RenderResult renders the live action-log lines for a result. Defaults to
	// a one-line denial/evidence summary.
	RenderResult func(res tools.Result) []string

	// StartMeta adds domain fields (environment, mode, ...) to the transcript
	// start event. ts, model, objective and max_steps are always included.
	StartMeta map[string]any

	// Confirm, when ConfirmRequired is set, is asked before each mutating tool
	// call; it returns true to allow the change. Nil while required denies the
	// change (fail closed).
	Confirm         func(tool, args string) bool
	ConfirmRequired bool
}

func (c *Config[B]) setDefaults() error {
	if c.MaxSteps <= 0 {
		c.MaxSteps = 100
	}
	if c.Objective == "" {
		c.Objective = "Investigate the target and report what you find."
	}
	if c.SystemPrompt == nil {
		return fmt.Errorf("agent: Config.SystemPrompt is required")
	}
	if c.RenderReport == nil {
		return fmt.Errorf("agent: Config.RenderReport is required")
	}
	if c.Out == nil {
		c.Out = func(string) {}
	}
	if c.ProgressInterval == 0 {
		c.ProgressInterval = 15 * time.Second
	}
	if c.MaxToolResult == 0 {
		c.MaxToolResult = 8 << 10
	}
	if c.RenderHeader == nil {
		c.RenderHeader = func(step int, tool, args string) string {
			return fmt.Sprintf("→ [%d] %s(%s)", step, tool, args)
		}
	}
	if c.RenderResult == nil {
		c.RenderResult = defaultRenderResult
	}
	return nil
}

// RunResult is the outcome of an agent run.
type RunResult struct {
	ReportPath string
	Report     string
	Steps      int
}

// maxTruncationRetries bounds how many consecutive truncated or filtered
// replies the loop will discard and retry before giving up.
const maxTruncationRetries = 3

// Run executes the agent loop and writes the final report into cfg.ReportDir.
func Run[B tools.Boundary](ctx context.Context, b B, client *llm.Client, reg *tools.Registry[B], cfg Config[B]) (*RunResult, error) {
	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}
	say := cfg.Out

	now := time.Now()

	// Transcript: a JSONL audit trail of the whole conversation (system prompt,
	// tool calls, boundary denials, evidence) written next to the report.
	reportPath := ""
	transcriptPath := ""
	var tw *os.File
	if cfg.ReportDir != "" {
		if err := os.MkdirAll(cfg.ReportDir, 0o755); err != nil {
			return nil, err
		}
		reportPath = filepath.Join(cfg.ReportDir, now.Format("report-20060102-150405.md"))
		transcriptPath = filepath.Join(cfg.ReportDir, now.Format("transcript-20060102-150405.jsonl"))
		if f, err := os.Create(transcriptPath); err == nil {
			tw = f
		}
	}
	defer func() {
		if tw != nil {
			tw.Close()
		}
	}()
	logMsg := func(m llm.Message) {
		if tw != nil {
			writeJSONL(tw, m)
		}
	}
	if tw != nil {
		start := map[string]any{
			"event":     "start",
			"ts":        now.UTC().Format(time.RFC3339),
			"model":     client.Model(),
			"objective": cfg.Objective,
			"max_steps": cfg.MaxSteps,
		}
		for k, v := range cfg.StartMeta {
			start[k] = v
		}
		writeJSONL(tw, start)
	}

	messages := []llm.Message{
		{Role: "system", Content: cfg.SystemPrompt(b, cfg.Objective, client.Model())},
		{Role: "user", Content: cfg.Objective + "\nBegin."},
	}
	logMsg(messages[0])
	logMsg(messages[1])
	specs := reg.Specs()

	steps := 0
	truncated := 0
	var final string
	for steps < cfg.MaxSteps {
		msg, finish, err := client.Chat(ctx, messages, specs)
		if err != nil {
			return nil, fmt.Errorf("step %d: %w", steps+1, err)
		}
		// A truncated or filtered reply is unreliable — its tool-call arguments
		// may be cut off mid-JSON. Discard it (keeping the protocol intact, since
		// an assistant message with tool_calls must be followed by tool results),
		// nudge the model, and retry the turn. Give up after a few in a row.
		if finish == "length" || finish == "content_filter" {
			truncated++
			if truncated >= maxTruncationRetries {
				say(fmt.Sprintf("· model response %s (discarded); giving up", finish))
				return nil, fmt.Errorf("model response repeatedly %s; aborting", finish)
			}
			say(fmt.Sprintf("· model response %s (discarded); retrying the turn", finish))
			note := llm.Message{Role: "user", Content: truncationNote(finish)}
			messages = append(messages, note)
			logMsg(note)
			continue
		}
		truncated = 0
		messages = append(messages, *msg)
		logMsg(*msg)
		if strings.TrimSpace(msg.Content) != "" {
			say(assistantLine(msg.Content))
		}
		if len(msg.ToolCalls) == 0 {
			final = msg.Content
			break
		}
		for _, tc := range msg.ToolCalls {
			steps++
			// The header goes out before the tool runs, so a slow action (an apt
			// install, a confirm prompt) is visible while it waits.
			say(cfg.RenderHeader(steps, tc.Function.Name, tc.Function.Arguments))
			res := dispatch(ctx, b, reg, cfg, tc.Function.Name, tc.Function.Arguments)
			raw, _ := json.Marshal(res)
			full := string(raw)
			messages = append(messages, llm.Message{Role: "tool", ToolCallID: tc.ID, Content: capToolResult(full, cfg.MaxToolResult)})
			// The transcript keeps the full result even when the model's copy is capped.
			logMsg(llm.Message{Role: "tool", ToolCallID: tc.ID, Content: full})
			for _, line := range cfg.RenderResult(res) {
				say(line)
			}
			if ctx.Err() != nil {
				break
			}
		}
		if ctx.Err() != nil {
			break
		}
	}

	if final == "" {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Step budget exhausted: force a final report from what the model has seen.
		say("· step budget reached; asking for the final report")
		budgetMsg := llm.Message{
			Role:    "user",
			Content: "You have reached the step budget. Write your final report now, based on the evidence gathered so far.",
		}
		messages = append(messages, budgetMsg)
		logMsg(budgetMsg)
		msg, _, err := client.Chat(ctx, messages, nil)
		if err != nil {
			return nil, fmt.Errorf("final report: %w", err)
		}
		messages = append(messages, *msg)
		logMsg(*msg)
		final = msg.Content
		say(assistantLine(final))
	}

	report := cfg.RenderReport(b, cfg.Objective, final, steps, transcriptPath)
	if cfg.ReportDir != "" {
		if err := os.WriteFile(reportPath, []byte(report), 0o644); err != nil {
			return nil, err
		}
		say("✓ report written to " + reportPath)
	}
	if tw != nil {
		writeJSONL(tw, map[string]any{
			"event":       "finish",
			"ts":          time.Now().UTC().Format(time.RFC3339),
			"steps":       steps,
			"report_path": reportPath,
		})
		tw.Close()
		tw = nil
		say("✓ transcript written to " + transcriptPath)
	}
	return &RunResult{ReportPath: reportPath, Report: report, Steps: steps}, nil
}

// dispatch runs one tool call, inserting the operator confirmation step for a
// mutating tool when the run requires it.
func dispatch[B tools.Boundary](ctx context.Context, b B, reg *tools.Registry[B], cfg Config[B], name, args string) tools.Result {
	if cfg.ConfirmRequired && reg.IsMutating(name) {
		if cfg.Confirm == nil || !cfg.Confirm(name, args) {
			return tools.Result{Tool: name, Allowed: false, Reason: "operator declined the change"}
		}
	}
	// Confirmation is done; heartbeat only the actual execution so the progress
	// lines never interleave with the operator's [y/N] prompt.
	return runWithProgress(cfg.Out, cfg.ProgressInterval, name, func() tools.Result {
		return reg.Run(ctx, b, name, args)
	})
}

// runWithProgress runs the tool and, while it is still executing, emits a
// heartbeat line through say every interval so a slow action stays visible.
// A non-positive interval runs the tool directly with no heartbeat.
func runWithProgress(say func(string), interval time.Duration, name string, run func() tools.Result) tools.Result {
	if interval <= 0 {
		return run()
	}
	done := make(chan tools.Result, 1)
	go func() { done <- run() }()
	t := time.NewTicker(interval)
	defer t.Stop()
	start := time.Now()
	for {
		select {
		case res := <-done:
			return res
		case <-t.C:
			say(fmt.Sprintf("  … %s still running (%s)", name, time.Since(start).Round(time.Second)))
		}
	}
}

// capToolResult bounds the tool-result text fed back to the model so one large
// result, or many stacked, cannot overflow the context window. A non-positive
// max, or content already within it, is returned unchanged; otherwise the text
// is cut to max bytes (trimming any split trailing rune) with a note pointing
// at the full result in the transcript.
func capToolResult(content string, max int) string {
	if max <= 0 || len(content) <= max {
		return content
	}
	dropped := len(content) - max
	return strings.ToValidUTF8(content[:max], "") +
		fmt.Sprintf("\n…[truncated %d bytes; full result in the transcript]", dropped)
}

func truncationNote(finish string) string {
	if finish == "content_filter" {
		return "Your previous response was blocked by a content filter and discarded. " +
			"Rephrase it and continue; do not assume any tool call ran."
	}
	return "Your previous response was cut off at the token limit and discarded. " +
		"Respond again more concisely; do not assume any tool call from it ran."
}

func writeJSONL(f *os.File, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	f.Write(append(raw, '\n'))
}

func assistantLine(content string) string {
	return "· " + strings.TrimSpace(content)
}

func defaultRenderResult(res tools.Result) []string {
	if !res.Allowed {
		return []string{"    ✗ DENIED: " + res.Reason}
	}
	if res.Reason != "" {
		return []string{"    ! " + res.Reason}
	}
	raw, _ := json.Marshal(res.Payload)
	s := string(raw)
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return []string{"    ← " + s}
}
