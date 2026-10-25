package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// defaultWordlist is the bundled top-1000 common-passwords list (SecLists
// Pwdb_top-1000.txt), copied into the image at this path (see Dockerfile).
const defaultWordlist = "/usr/share/mole/wordlists/top1000.txt"

const (
	// crackDefaultTimeout is the default crack window; crackMaxTimeout is
	// the hard cap — offline cracking is bounded in code.
	crackDefaultTimeout = 120 * time.Second
	crackMaxTimeout     = 600 * time.Second
	// crackOutputCap caps the hashcat output returned to the model (8 KB,
	// like the other external tools).
	crackOutputCap = 8192
)

// crackModeNames maps the hashcat modes this tool auto-detects (or accepts
// explicitly) to human-readable names for the result.
var crackModeNames = map[int]string{
	0:    "MD5",
	100:  "NTLM",
	300:  "SHA1",
	400:  "SHA256",
	600:  "SHA512",
	1800: "SHA256-CRYPT",
	3000: "LM",
	5000: "MD5-CRYPT",
	7400: "bcrypt",
	7500: "SHA512-CRYPT",
}

var (
	crackHex   = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	crackCrack = regexp.MustCompile(`^[^:]+:(.+)$`)
)

// Crack attacks a hash captured during the run with a dictionary attack
// (hashcat, attack mode 0). It is offline: the only target contact is the
// scope gate on 'source' — the host the hash came from — which is what keeps
// this tool inside the engagement's scope. Hash type is auto-detected from
// the hash format; pass 'mode' to override (e.g. a 32-char hex digest that
// is MD5, not NTLM).
type Crack struct{}

func (Crack) Name() string   { return "crack" }
func (Crack) Mutating() bool { return true }

func (Crack) Description() string {
	return "Offline dictionary attack (hashcat, wordlist mode) on a hash found during the engagement. " +
		"Pass the hash and 'source', the in-scope host it was captured from (scope-gated). " +
		"Hash type is auto-detected from the format (NTLM/SHA1/SHA256/SHA512/LM/bcrypt/SHA- and MD5-crypt); " +
		"pass 'mode' to override the detection. Uses the bundled top-1000 wordlist by default; " +
		"returns the cracked password when found, otherwise reports the hash as uncracked."
}

func (Crack) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"hash":     map[string]any{"type": "string", "description": "The hash to attack (e.g. an NTLM, MD5, SHA-*, LM, bcrypt or crypt hash)"},
			"source":   map[string]any{"type": "string", "description": "In-scope host the hash was captured from (scope-gated)"},
			"mode":     map[string]any{"type": "integer", "description": "Optional hashcat mode to override auto-detection (e.g. 0 for MD5, 100 for NTLM)"},
			"wordlist": map[string]any{"type": "string", "description": "Optional wordlist path; defaults to the bundled top-1000 list"},
			"timeout":  map[string]any{"type": "integer", "description": "Optional crack window in seconds (default 120, max 600)"},
		},
		"required": []any{"hash", "source"},
	}
}

// detectHashMode infers the hashcat mode from the hash format. It returns
// -1 when the format is unrecognised and the model must pass 'mode' itself.
func detectHashMode(hash string) int {
	h := strings.TrimSpace(hash)
	switch {
	case strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$"):
		return 7400 // bcrypt
	case strings.HasPrefix(h, "$6$"):
		return 7500 // SHA512-CRYPT
	case strings.HasPrefix(h, "$5$"):
		return 1800 // SHA256-CRYPT
	case strings.HasPrefix(h, "$1$"):
		return 5000 // MD5-CRYPT
	case crackHex.MatchString(h):
		switch len(h) {
		case 32:
			// The LM null half (hash of 8 NUL bytes, present when the
			// password is at most 7 chars) is the constant
			// aad3b435b51404ee; plain 32-hex defaults to NTLM (an MD5 of
			// the same length is a model override via 'mode').
			if strings.EqualFold(h[16:], "aad3b435b51404ee") {
				return 3000 // LM
			}
			return 100 // NTLM
		case 40:
			return 300 // SHA1
		case 64:
			return 400 // SHA256
		case 128:
			return 600 // SHA512
		}
	}
	return -1
}

func (Crack) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	hash := strArg(args, "hash")
	source := strArg(args, "source")
	if hash == "" {
		return core.Result{Tool: "crack", Allowed: false, Reason: "missing required argument 'hash'"}
	}
	if source == "" {
		return core.Result{Tool: "crack", Allowed: false, Reason: "missing required argument 'source' (the in-scope host the hash came from)"}
	}
	// The listener-side gate: the hash must come from an in-scope host. The
	// crack itself is offline and touches no target.
	ok, reason := s.CheckTarget(ctx, source, nil)
	if !ok {
		return core.Result{Tool: "crack", Target: source, Allowed: false, Reason: reason}
	}
	mode := intArg(args, "mode", -1)
	if mode == -1 {
		mode = detectHashMode(hash)
		if mode == -1 {
			return core.Result{Tool: "crack", Target: source, Allowed: false,
				Reason: "cannot detect the hash type from its format; pass 'mode' explicitly (e.g. 0 for MD5, 100 for NTLM)",
			}
		}
	}
	if _, ok := crackModeNames[mode]; !ok {
		return core.Result{Tool: "crack", Target: source, Allowed: false,
			Reason: fmt.Sprintf("unsupported hashcat mode %d; supported: %s", mode, crackModeList()),
		}
	}
	wordlist := strArg(args, "wordlist")
	if wordlist == "" {
		wordlist = defaultWordlist
	}
	timeout := time.Duration(intArg(args, "timeout", int(crackDefaultTimeout/time.Second))) * time.Second
	if timeout > crackMaxTimeout {
		timeout = crackMaxTimeout
	}
	if _, err := exec.LookPath("hashcat"); err != nil {
		return core.Result{Tool: "crack", Target: source, Allowed: true,
			Reason: "hashcat is not installed in this environment; offline cracking is unavailable",
		}
	}
	if _, err := os.Stat(wordlist); err != nil {
		return core.Result{Tool: "crack", Target: source, Allowed: true,
			Reason: fmt.Sprintf("wordlist %s is not available: %v", wordlist, err),
		}
	}
	// hashcat takes the hash as a positional file, not a string: write it to
	// a throwaway file and point hashcat at that.
	dir, err := os.MkdirTemp("", "mole-crack-")
	if err != nil {
		return core.Result{Tool: "crack", Target: source, Allowed: true, Reason: fmt.Sprintf("temp dir: %v", err)}
	}
	defer os.RemoveAll(dir)
	hashFile := filepath.Join(dir, "hash.txt")
	if err := os.WriteFile(hashFile, []byte(strings.TrimSpace(hash)+"\n"), 0o600); err != nil {
		return core.Result{Tool: "crack", Target: source, Allowed: true, Reason: fmt.Sprintf("write hash file: %v", err)}
	}
	potFile := filepath.Join(dir, "potfile")
	cmdArgs := []string{"-m", strconv.Itoa(mode), "-a", "0", "-c", "--quiet",
		"--potfile-path=" + potFile, hashFile, wordlist}

	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, rerr := exec.CommandContext(cctx, "hashcat", cmdArgs...).CombinedOutput()
	duration := time.Since(start).Round(time.Second)
	if len(out) > crackOutputCap {
		out = out[:crackOutputCap]
	}

	res := core.Result{Tool: "crack", Target: source, Allowed: true, Payload: map[string]any{
		"mode":      mode,
		"mode_name": crackModeNames[mode],
		"cracked":   false,
		"duration":  duration.String(),
		"wordlist":  wordlist,
		"command":   "hashcat " + strings.Join(cmdArgs, " "),
		"output":    string(out),
	}}
	if rerr != nil {
		// A timed-out or failed run is not a gate denial: the crack simply
		// did not finish. A context deadline is reported as such.
		if cctx.Err() == context.DeadlineExceeded {
			res.Reason = fmt.Sprintf("crack timed out after %s without cracking the hash", duration)
		} else {
			res.Reason = fmt.Sprintf("hashcat exited: %v", rerr)
		}
		return res
	}
	// hashcat's exit code does not signal a crack; with --quiet the only
	// output lines are `hash:password` for each cracked hash.
	pl := res.Payload.(map[string]any)
	for _, line := range strings.Split(string(out), "\n") {
		if m := crackCrack.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			pl["cracked"] = true
			pl["password"] = m[1]
			break
		}
	}
	return res
}

// crackModeList renders the supported mode set for denial reasons, in
// ascending mode order.
func crackModeList() string {
	modes := []int{0, 100, 300, 400, 600, 1800, 3000, 5000, 7400, 7500}
	parts := make([]string, 0, len(modes))
	for _, m := range modes {
		parts = append(parts, fmt.Sprintf("%d=%s", m, crackModeNames[m]))
	}
	return strings.Join(parts, ", ")
}
