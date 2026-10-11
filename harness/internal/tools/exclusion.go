package tools

import (
	"context"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// NoteOutOfScope records a runtime exclusion: a target the agent judged out
// of scope (e.g. infrastructure discovered during recon that it did not
// authorise), asking the gate to enforce that judgment on every subsequent
// run. Exclusions only narrow scope: the gate refuses to record a target
// that is not under a recorded in-scope pattern, and the sidecar
// exclusions.yaml is written next to scope.yaml, which is never modified.
type NoteOutOfScope struct{}

func (NoteOutOfScope) Name() string   { return "note_out_of_scope" }
func (NoteOutOfScope) Mutating() bool { return false }

func (NoteOutOfScope) Description() string {
	return "Record a target you judge to be out of scope (e.g. infrastructure you discovered that you did not authorise), so the gate denies all operations against it on every run. " +
		"Call this before probing such a target. It cannot widen scope: the target must already be under a recorded in-scope pattern."
}

func (NoteOutOfScope) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"target": map[string]any{
				"type":        "string",
				"description": "The target to exclude (hostname or IP address). Must be under a recorded in-scope pattern.",
			},
			"reason": map[string]any{
				"type":        "string",
				"description": "Why this target is out of scope for the engagement. Recorded for the audit trail.",
			},
		},
		"required": []string{"target", "reason"},
	}
}

func (NoteOutOfScope) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	target := strArg(args, "target")
	reason := strArg(args, "reason")
	if target == "" {
		return core.Result{Tool: "note_out_of_scope", Allowed: false, Reason: "missing required argument: target"}
	}
	if reason == "" {
		return core.Result{Tool: "note_out_of_scope", Target: target, Allowed: false,
			Reason: "missing required argument: reason (record why this target is out of scope)"}
	}
	if err := s.Exclude(target, reason); err != nil {
		return core.Result{Tool: "note_out_of_scope", Target: target, Allowed: false, Reason: err.Error()}
	}
	return core.Result{
		Tool:    "note_out_of_scope",
		Target:  target,
		Allowed: true,
		Reason:  "exclusion recorded; the gate now denies all operations against this target on every run",
		Payload: map[string]any{"reason": reason},
	}
}
