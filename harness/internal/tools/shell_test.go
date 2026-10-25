package tools

import (
	"os/exec"
	"strings"
	"testing"
)

func TestShellEcho(t *testing.T) {
	res := (Shell{}).Run(testCtx, testScope(), map[string]any{"command": "echo mole-shell"})
	if !res.Allowed {
		t.Fatalf("shell echo denied: %s", res.Reason)
	}
	out, _ := res.Payload.(map[string]any)["output"].(string)
	if !strings.Contains(out, "mole-shell") {
		t.Errorf("output = %q, want it to contain %q", out, "mole-shell")
	}
}

func TestShellPython3(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed on this host")
	}
	res := (Shell{}).Run(testCtx, testScope(), map[string]any{"command": `python3 -c "print(6*7)"`})
	if !res.Allowed {
		t.Fatalf("shell python3 denied: %s", res.Reason)
	}
	out, _ := res.Payload.(map[string]any)["output"].(string)
	if !strings.Contains(out, "42") {
		t.Errorf("output = %q, want it to contain %q", out, "42")
	}
}

func TestShellMultilineScript(t *testing.T) {
	script := `for i in 1 2 3; do
  echo "host-$i in scope"
done`
	res := (Shell{}).Run(testCtx, testScope(), map[string]any{"command": script})
	if !res.Allowed {
		t.Fatalf("shell script denied: %s", res.Reason)
	}
	out, _ := res.Payload.(map[string]any)["output"].(string)
	for _, want := range []string{"host-1", "host-2", "host-3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output = %q, want it to contain %q", out, want)
		}
	}
}

func TestShellExitCode(t *testing.T) {
	res := (Shell{}).Run(testCtx, testScope(), map[string]any{"command": "exit 3"})
	if !res.Allowed {
		t.Fatalf("shell exit denied: %s", res.Reason)
	}
	if !strings.Contains(res.Reason, "exited with code 3") {
		t.Errorf("reason = %q, want exit code 3 reported", res.Reason)
	}
}

func TestShellTimeout(t *testing.T) {
	res := (Shell{}).Run(testCtx, testScope(), map[string]any{"command": "sleep 10", "timeout": 1})
	if !res.Allowed {
		t.Fatalf("shell timeout denied: %s", res.Reason)
	}
	if !strings.Contains(res.Reason, "timed out") {
		t.Errorf("reason = %q, want a timeout report", res.Reason)
	}
}

func TestShellCommandCap(t *testing.T) {
	long := strings.Repeat("a", shellCommandCap+1)
	res := (Shell{}).Run(testCtx, testScope(), map[string]any{"command": long})
	if res.Allowed {
		t.Error("over-cap command was allowed")
	}
	if !strings.Contains(res.Reason, "exceeds") {
		t.Errorf("reason = %q, want a length-cap denial", res.Reason)
	}
}

func TestShellMissingCommand(t *testing.T) {
	if res := (Shell{}).Run(testCtx, testScope(), map[string]any{}); res.Allowed {
		t.Error("missing command was allowed")
	}
}

func TestShellRegisteredInBothModes(t *testing.T) {
	// Always available: reconnaissance engagements can adapt techniques with
	// local scripts too, so the tool must survive the mutate gate.
	if !registered(NewRegistry(false, newLedger(t), newKB()), "shell") {
		t.Error("shell missing from the reconnaissance registry")
	}
	if !registered(NewRegistry(true, newLedger(t), newKB()), "shell") {
		t.Error("shell missing from the vulnerability-scanning registry")
	}
}

func TestShellNotMutating(t *testing.T) {
	if (Shell{}).Mutating() {
		t.Error("shell must not be flagged mutating: it runs locally, target safety rests on prompt rules and the transcript")
	}
}
