package tools

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// shellOutputCap caps the output returned to the model (8 KB, like exec and
// http_request).
const shellOutputCap = 8192

// shellCommandCap bounds a single script: long enough for a small adaptation
// script (exploit with patched parameters, a loop over in-scope hosts), short
// enough to keep the transcript readable.
const shellCommandCap = 16384

// shellDefaultTimeout / shellMaxTimeout bound the per-call timeout in seconds.
const (
	shellDefaultTimeout = 60
	shellMaxTimeout     = 300
)

// Shell runs a shell command locally inside the harness container (bash and
// python3 are installed). It exists so the agent can adapt a public exploit or
// technique into a small script when stock commands don't fit — e.g. patching
// an exploit's target URL, looping it over in-scope hosts, or parsing its
// output. The script is passed as the 'command' argument, so it is recorded
// in the transcript in full (auditability).
//
// Mutating reports false deliberately: the command runs in the harness, not on
// the target, so it never changes target state by itself. The risk of a local
// command reaching out-of-scope systems is mitigated by prompt rules (in-scope
// targets only) and the transcript audit, not by the registry gate.
type Shell struct{}

func (Shell) Name() string   { return "shell" }
func (Shell) Mutating() bool { return false }

func (Shell) Description() string {
	return "Run a shell command locally in the harness (bash and python3 are installed). " +
		"Use it to adapt a public exploit or technique into a small script when stock commands don't fit: " +
		"patch the exploit's hardcoded target, loop it over in-scope hosts, parse its output, assemble a payload. " +
		"The script is passed as 'command' and is recorded in the transcript verbatim — cite it in record_finding when you use it. " +
		"Network access from scripts is allowed only toward in-scope targets; never touch out-of-scope hosts. " +
		"Keep scripts minimal and non-destructive (timeout in seconds, default 60, max 300)."
}

func (Shell) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"command": map[string]any{
				"type":        "string",
				"description": "Shell command or script to run in the harness (bash -c). Multi-line scripts allowed.",
			},
			"timeout": map[string]any{
				"type":        "integer",
				"description": "Optional: timeout in seconds (default 60, capped at 300).",
			},
		},
		"required": []any{"command"},
	}
}

// shellTimeout maps a seconds argument to a clamped timeout: default 60 s,
// max 300 s.
func shellTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		seconds = shellDefaultTimeout
	}
	if seconds > shellMaxTimeout {
		seconds = shellMaxTimeout
	}
	return time.Duration(seconds) * time.Second
}

func (Shell) Run(ctx context.Context, _ *scope.Scope, args map[string]any) core.Result {
	const name = "shell"
	cmd := strArg(args, "command")
	if cmd == "" {
		return core.Result{Tool: name, Allowed: false, Reason: "missing required argument 'command'"}
	}
	if len(cmd) > shellCommandCap {
		return core.Result{Tool: name, Allowed: false,
			Reason: fmt.Sprintf("shell: command exceeds %d characters", shellCommandCap)}
	}

	rctx, cancel := context.WithTimeout(ctx, shellTimeout(intArg(args, "timeout", 0)))
	defer cancel()

	out, err := exec.CommandContext(rctx, "bash", "-c", cmd).CombinedOutput()
	text := string(out)
	pl := map[string]any{"command": cmd}
	res := core.Result{Tool: name, Allowed: true, Payload: pl}
	if len(text) > shellOutputCap {
		text = text[:shellOutputCap] + "…"
	}
	pl["output"] = text
	if err != nil {
		if rctx.Err() == context.DeadlineExceeded {
			res.Reason = fmt.Sprintf("shell: command timed out after %d s", int(shellTimeout(intArg(args, "timeout", 0)).Seconds()))
		} else if ee, ok := err.(*exec.ExitError); ok {
			res.Reason = fmt.Sprintf("shell: command exited with code %d", ee.ExitCode())
			pl["exit_code"] = ee.ExitCode()
		} else {
			res.Reason = "shell: " + err.Error()
		}
	}
	return res
}
