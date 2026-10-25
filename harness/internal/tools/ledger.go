package tools

import (
	"context"
	"fmt"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/ledger"
	"mole/internal/scope"
)

// RecordFinding records a significant finding in the engagement's findings
// ledger. The ledger is the agent's working memory: the model records a
// finding as it makes it, and the ledger's state is re-injected into its
// context every step. These tools act on the ledger, not on targets, so they
// are not mutating in the scope-gate sense.
type RecordFinding struct {
	L *ledger.Ledger
}

func (RecordFinding) Name() string   { return "record_finding" }
func (RecordFinding) Mutating() bool { return false }

func (RecordFinding) Description() string {
	return "Record a significant finding in the engagement's findings ledger: what you observed, on which target, and the probe that found it. " +
		"Record findings as you make them — one call per finding — so nothing falls out of memory; the ledger is re-shown to you every step. " +
		"Each finding gets an ID (F1, F2, ...) you reference with update_finding."
}

func (RecordFinding) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"summary": map[string]any{
				"type":        "string",
				"description": "The finding in one line, e.g. 'OpenSSH 8.9 on 22/tcp' or 'admin panel on /wp-login.php'.",
			},
			"target": map[string]any{
				"type":        "string",
				"description": "The target the finding is about (host, port, service, URL). Optional for engagement-wide findings.",
			},
			"source": map[string]any{
				"type":        "string",
				"description": "The probe that found it, e.g. 'nmap 144.76.67.91' or 'http_probe http://host/admin'.",
			},
			"evidence": map[string]any{
				"type":        "string",
				"description": "Short quoted observation backing the finding.",
			},
		},
		"required": []string{"summary"},
	}
}

func (t RecordFinding) Run(_ context.Context, _ *scope.Scope, args map[string]any) core.Result {
	summary := strArg(args, "summary")
	if summary == "" {
		return core.Result{Tool: "record_finding", Allowed: false, Reason: "missing required argument: summary"}
	}
	f, err := t.L.Record(summary, strArg(args, "target"), strArg(args, "source"), strArg(args, "evidence"))
	if err != nil {
		return core.Result{Tool: "record_finding", Allowed: false, Reason: err.Error()}
	}
	return core.Result{
		Tool:    "record_finding",
		Target:  f.Target,
		Allowed: true,
		Reason:  "finding " + f.ID + " recorded",
		Payload: map[string]any{"id": f.ID, "status": string(f.Status)},
	}
}

// UpdateFinding advances a recorded finding through its lifecycle: investigated
// when it has been followed up, exploited when something acted on it (with the
// action and outcome), dropped when it is not worth pursuing (with a reason).
type UpdateFinding struct {
	L *ledger.Ledger
}

func (UpdateFinding) Name() string   { return "update_finding" }
func (UpdateFinding) Mutating() bool { return false }

func (UpdateFinding) Description() string {
	return "Update a recorded finding's lifecycle status (investigated, exploited, or dropped) and, when you acted on it, what you did and the outcome. " +
		"Call this when you follow up on, exploit, or drop a finding, so the ledger — and the final report's finding → exploitation chain — stays accurate. " +
		"Use dropped with a note when a finding is not worth pursuing."
}

func (UpdateFinding) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id": map[string]any{
				"type":        "string",
				"description": "The finding ID returned by record_finding, e.g. 'F3'.",
			},
			"status": map[string]any{
				"type":        "string",
				"enum":        []string{"new", "investigated", "exploited", "dropped"},
				"description": "The new lifecycle status of the finding.",
			},
			"exploit": map[string]any{
				"type":        "string",
				"description": "What acted on the finding and the outcome, when the status is exploited.",
			},
			"note": map[string]any{
				"type":        "string",
				"description": "A short note, e.g. why the finding was dropped.",
			},
		},
		"required": []string{"id", "status"},
	}
}

func (t UpdateFinding) Run(_ context.Context, _ *scope.Scope, args map[string]any) core.Result {
	id := strArg(args, "id")
	if id == "" {
		return core.Result{Tool: "update_finding", Allowed: false, Reason: "missing required argument: id"}
	}
	status := strArg(args, "status")
	if status == "" {
		return core.Result{Tool: "update_finding", Allowed: false, Reason: "missing required argument: status"}
	}
	if _, ok := ledger.ParseStatus(status); !ok {
		return core.Result{Tool: "update_finding", Target: id, Allowed: false,
			Reason: fmt.Sprintf("unknown status %q (want new, investigated, exploited, dropped)", status)}
	}
	f, err := t.L.Update(id, status, strArg(args, "exploit"), strArg(args, "note"))
	if err != nil {
		return core.Result{Tool: "update_finding", Target: id, Allowed: false, Reason: err.Error()}
	}
	return core.Result{
		Tool:    "update_finding",
		Target:  f.ID,
		Allowed: true,
		Reason:  "finding " + f.ID + " updated to " + string(f.Status),
		Payload: map[string]any{"id": f.ID, "status": string(f.Status)},
	}
}
