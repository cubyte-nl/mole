package tools

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNetcatRegistryGating(t *testing.T) {
	s := testScope("127.0.0.1")
	// A reconnaissance engagement cannot reach netcat at all.
	if res := NewRegistry(false, newLedger(t), newKB()).Run(testCtx, s, "netcat", `{"source":"127.0.0.1"}`); res.Allowed {
		t.Error("netcat reachable in a reconnaissance registry")
	}
	if !registered(NewRegistry(true, newLedger(t), newKB()), "netcat") {
		t.Error("netcat not registered in a vuln-scanning registry")
	}
}

func TestNetcatGate(t *testing.T) {
	s := testScope("127.0.0.1")

	// Missing source (the scope anchor) is denied.
	if res := (&Netcat{}).Run(testCtx, s, map[string]any{}); res.Allowed {
		t.Error("missing source was allowed")
	}

	// The expected connecting host must be in scope.
	if res := (&Netcat{}).Run(testCtx, s, map[string]any{"source": "definitely-not-a-host.invalid"}); res.Allowed {
		t.Errorf("out-of-scope source was allowed: %s", res.Reason)
	}

	// An out-of-range port is denied.
	if res := (&Netcat{}).Run(testCtx, s, map[string]any{"source": "127.0.0.1", "port": 70000}); res.Allowed {
		t.Errorf("out-of-range port was allowed: %s", res.Reason)
	}

	// An unknown action is denied.
	if res := (&Netcat{}).Run(testCtx, s, map[string]any{"source": "127.0.0.1", "action": "explode"}); res.Allowed {
		t.Errorf("invalid action was allowed: %s", res.Reason)
	}
}

func TestNetcatCollectWithoutArm(t *testing.T) {
	s := testScope("127.0.0.1")
	if res := (&Netcat{}).Run(testCtx, s, map[string]any{"action": "collect"}); res.Allowed {
		t.Errorf("collect without arm was allowed: %s", res.Reason)
	}
}

func TestNetcatPortInUse(t *testing.T) {
	if _, err := exec.LookPath("ncat"); err != nil {
		t.Skip("ncat not installed")
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	s := testScope("127.0.0.1")
	res := (&Netcat{}).Run(testCtx, s, map[string]any{"source": "127.0.0.1", "port": port})
	if res.Allowed {
		t.Errorf("arming on a busy port was allowed: %v", res.Payload)
	}
}

func TestNetcatRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("ncat"); err != nil {
		t.Skip("ncat not installed")
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	n := &Netcat{}
	s := testScope("127.0.0.1")
	res := n.Run(testCtx, s, map[string]any{"source": "127.0.0.1", "port": port, "timeout": 30})
	if !res.Allowed {
		t.Fatalf("arm denied: %s", res.Reason)
	}
	capture, _ := res.Payload.(map[string]any)["capture"].(string)
	// Tear the listener down and remove its capture file afterwards.
	defer func() {
		n.mu.Lock()
		n.stopLocked()
		n.mu.Unlock()
		if capture != "" {
			os.Remove(capture)
		}
	}()

	// Wait for the listener to start accepting, then send data.
	var conn net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("listener did not start accepting connections")
	}
	sent := "mole-ncat-roundtrip\n"
	if _, err := conn.Write([]byte(sent)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	// Poll collect until the data lands (ncat streams into the capture file).
	var got string
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cres := n.Run(testCtx, s, map[string]any{"action": "collect"})
		if !cres.Allowed {
			t.Fatalf("collect denied: %s", cres.Reason)
		}
		got, _ = cres.Payload.(map[string]any)["data"].(string)
		if strings.Contains(got, "mole-ncat-roundtrip") {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !strings.Contains(got, "mole-ncat-roundtrip") {
		t.Errorf("captured data %q does not contain the sent payload", got)
	}
}
