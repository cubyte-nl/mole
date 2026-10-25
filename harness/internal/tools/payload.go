package tools

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

const (
	// payloadDefaultTimeout bounds one msfvenom invocation;
	// payloadMaxTimeout is the hard cap.
	payloadDefaultTimeout = 60 * time.Second
	payloadMaxTimeout     = 120 * time.Second
	// payloadOutputCap caps the generated payload text returned to the model
	// (8 KB, like the other tools).
	payloadOutputCap = 8192
)

// msfvenomTokens matches a payload name, a format name, or one side of an
// option: letters, digits and a small path-like set. Anything with a shell
// metacharacter (;, |, &, $, backtick, space, …) fails here and is denied
// before it can reach a command line.
var msfvenomTokens = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/._-]*$`)

var msfvenomOption = regexp.MustCompile(`^([A-Za-z0-9_]+)=([A-Za-z0-9._:/-]*)$`)

// Payload generates exploit payloads with msfvenom — the stateless part of
// Metasploit. It never runs msfconsole and never connects anywhere: the
// target is scope-gated (the box the payload is aimed at) and the tool only
// produces text for the model to use. Typical use with the netcat listener:
// arm netcat first, then generate a reverse shell with the listener's IP and
// port as LHOST/LPORT.
type Payload struct{}

func (Payload) Name() string   { return "payload" }
func (Payload) Mutating() bool { return true }

func (Payload) Description() string {
	return "Generate an exploit payload with msfvenom (Metasploit payload generation; stateless, no listener involved). " +
		"Pass 'target' (the in-scope host the payload is aimed at, scope-gated), 'payload' (e.g. linux/x64/shell_reverse_tcp), " +
		"'format' (default 'cmd'; also e.g. raw, elf, exe, python, powershell, bash_reverse_tcp), " +
		"and options as space-separated KEY=VALUE pairs — LHOST/LPORT for a reverse payload. " +
		"Returns the generated payload text. Pair with the netcat listener: arm netcat first, use its lhost/port as LHOST/LPORT."
}

func (Payload) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"target":  map[string]any{"type": "string", "description": "In-scope host the payload is aimed at (scope-gated)"},
			"payload": map[string]any{"type": "string", "description": `msfvenom payload name, e.g. "linux/x64/shell_reverse_tcp", "windows/x64/meterpreter/reverse_tcp"`},
			"format":  map[string]any{"type": "string", "description": `Output format, default "cmd"; e.g. "raw", "elf", "exe", "python", "powershell", "sh", "bash"`},
			"lhost":   map[string]any{"type": "string", "description": "Listener host for reverse payloads (the harness IP from a netcat arm)"},
			"lport":   map[string]any{"type": "integer", "description": "Listener port for reverse payloads (the netcat listener port)"},
			"options": map[string]any{"type": "string", "description": `Extra msfvenom options as space-separated KEY=VALUE pairs, e.g. "EXITFUNC=thread"`},
			"timeout": map[string]any{"type": "integer", "description": "Optional timeout in seconds (default 60, max 120)"},
		},
		"required": []any{"target", "payload"},
	}
}

func (p Payload) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	target := strArg(args, "target")
	if target == "" {
		return core.Result{Tool: "payload", Allowed: false, Reason: "missing required argument 'target'"}
	}
	payloadName := strArg(args, "payload")
	if payloadName == "" {
		return core.Result{Tool: "payload", Allowed: false, Reason: "missing required argument 'payload'"}
	}
	if !msfvenomTokens.MatchString(payloadName) {
		return core.Result{Tool: "payload", Target: target, Allowed: false,
			Reason: fmt.Sprintf("payload name %q contains invalid characters", payloadName),
		}
	}
	format := strArg(args, "format")
	if format == "" {
		format = "cmd"
	}
	if !msfvenomTokens.MatchString(format) {
		return core.Result{Tool: "payload", Target: target, Allowed: false,
			Reason: fmt.Sprintf("format %q contains invalid characters", format),
		}
	}
	ok, reason := s.CheckTarget(ctx, target, nil)
	if !ok {
		return core.Result{Tool: "payload", Target: target, Allowed: false, Reason: reason}
	}
	lhost := strArg(args, "lhost")
	if lhost != "" && !msfvenomTokens.MatchString(lhost) {
		return core.Result{Tool: "payload", Target: target, Allowed: false,
			Reason: fmt.Sprintf("lhost %q contains invalid characters", lhost),
		}
	}
	lport := intArg(args, "lport", 0)
	if lport != 0 && (lport < 1 || lport > 65535) {
		return core.Result{Tool: "payload", Target: target, Allowed: false, Reason: fmt.Sprintf("lport %d out of range 1-65535", lport)}
	}
	opts := strArg(args, "options")
	for _, tok := range strings.Fields(opts) {
		if m := msfvenomOption.FindStringSubmatch(tok); m == nil {
			return core.Result{Tool: "payload", Target: target, Allowed: false,
				Reason: fmt.Sprintf("option %q is not a valid KEY=VALUE pair (letters/digits/underscore key, simple value)", tok),
			}
		}
	}
	timeout := time.Duration(intArg(args, "timeout", int(payloadDefaultTimeout/time.Second))) * time.Second
	if timeout > payloadMaxTimeout {
		timeout = payloadMaxTimeout
	}
	if _, err := exec.LookPath("msfvenom"); err != nil {
		return core.Result{Tool: "payload", Target: target, Allowed: true,
			Reason: "msfvenom is not installed in this environment; payload generation is unavailable"}
	}

	cmdArgs := []string{"-p", payloadName, "-f", format, "-q"}
	if lhost != "" {
		cmdArgs = append(cmdArgs, "LHOST="+lhost)
	}
	if lport != 0 {
		cmdArgs = append(cmdArgs, "LPORT="+strconv.Itoa(lport))
	}
	cmdArgs = append(cmdArgs, strings.Fields(opts)...)

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, "msfvenom", cmdArgs...).CombinedOutput()
	if len(out) > payloadOutputCap {
		out = out[:payloadOutputCap]
	}
	res := core.Result{Tool: "payload", Target: target, Allowed: true, Payload: map[string]any{
		"payload": payloadName,
		"format":  format,
		"command": "msfvenom " + strings.Join(cmdArgs, " "),
		"output":  string(out),
	}}
	if err != nil {
		res.Reason = fmt.Sprintf("msfvenom exited: %v", err)
	}
	return res
}
