package tools

import (
	"os/exec"
	"strings"
	"testing"
)

func TestPayloadRegistryGating(t *testing.T) {
	s := testScope("127.0.0.1")
	// A reconnaissance engagement cannot reach payload at all.
	if res := NewRegistry(false, newLedger(t), newKB()).Run(testCtx, s, "payload", `{"target":"127.0.0.1","payload":"linux/x64/shell_reverse_tcp"}`); res.Allowed {
		t.Error("payload reachable in a reconnaissance registry")
	}
	if !registered(NewRegistry(true, newLedger(t), newKB()), "payload") {
		t.Error("payload not registered in a vuln-scanning registry")
	}
}

func TestPayloadGate(t *testing.T) {
	s := testScope("127.0.0.1")

	// Missing target is denied before anything else.
	if res := (Payload{}).Run(testCtx, s, map[string]any{"payload": "linux/x64/shell_reverse_tcp"}); res.Allowed {
		t.Error("missing target was allowed")
	}

	// Missing payload name is denied.
	if res := (Payload{}).Run(testCtx, s, map[string]any{"target": "127.0.0.1"}); res.Allowed {
		t.Error("missing payload was allowed")
	}

	// Out-of-scope target is gate-denied.
	if res := (Payload{}).Run(testCtx, s, map[string]any{
		"target":  "definitely-not-a-host.invalid",
		"payload": "linux/x64/shell_reverse_tcp",
	}); res.Allowed {
		t.Errorf("out-of-scope target was allowed: %s", res.Reason)
	}
}

func TestPayloadArgValidation(t *testing.T) {
	s := testScope("127.0.0.1")

	// A payload name with shell metacharacters is denied — it must never
	// reach a command line.
	badNames := []string{"linux/x64/shell; rm -rf /", "payload $(id)", "a`id`", "win|cat"}
	for _, name := range badNames {
		if res := (Payload{}).Run(testCtx, s, map[string]any{"target": "127.0.0.1", "payload": name}); res.Allowed {
			t.Errorf("invalid payload name %q was allowed: %s", name, res.Reason)
		}
	}

	// A bad format is denied the same way.
	if res := (Payload{}).Run(testCtx, s, map[string]any{"target": "127.0.0.1", "payload": "linux/x64/shell_reverse_tcp", "format": "cmd; id"}); res.Allowed {
		t.Errorf("invalid format was allowed: %s", res.Reason)
	}

	// Options must be KEY=VALUE pairs with simple values.
	badOpts := []string{"LHOST=1.2.3.4; id", "LPORT=4444 && id", "noequals", "KEY=va lue", "KEY=$(id)"}
	for _, o := range badOpts {
		if res := (Payload{}).Run(testCtx, s, map[string]any{"target": "127.0.0.1", "payload": "linux/x64/shell_reverse_tcp", "options": o}); res.Allowed {
			t.Errorf("invalid option %q was allowed: %s", o, res.Reason)
		}
	}

	// A bad lhost is denied; an out-of-range lport is denied.
	if res := (Payload{}).Run(testCtx, s, map[string]any{"target": "127.0.0.1", "payload": "linux/x64/shell_reverse_tcp", "lhost": "1.2.3.4; id"}); res.Allowed {
		t.Errorf("invalid lhost was allowed: %s", res.Reason)
	}
	if res := (Payload{}).Run(testCtx, s, map[string]any{"target": "127.0.0.1", "payload": "linux/x64/shell_reverse_tcp", "lport": 70000}); res.Allowed {
		t.Errorf("out-of-range lport was allowed: %s", res.Reason)
	}
}

func TestPayloadRealRun(t *testing.T) {
	if _, err := exec.LookPath("msfvenom"); err != nil {
		t.Skip("msfvenom not installed")
	}
	s := testScope("127.0.0.1")
	res := (Payload{}).Run(testCtx, s, map[string]any{
		"target":  "127.0.0.1",
		"payload": "linux/x64/shell_reverse_tcp",
		"format":  "cmd",
		"lhost":   "1.2.3.4",
		"lport":   4444,
	})
	if !res.Allowed {
		t.Fatalf("payload denied: %s", res.Reason)
	}
	out, _ := res.Payload.(map[string]any)["output"].(string)
	if !strings.Contains(out, "/dev/tcp/1.2.3.4/4444") {
		t.Errorf("generated payload does not reference the listener:\n%s", out)
	}
}
