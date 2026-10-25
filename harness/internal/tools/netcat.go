package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

const (
	// netcatDefaultPort is the classic reverse-shell listener port.
	netcatDefaultPort = 4444
	// netcatDefaultLifetime is how long an armed listener stays up;
	// netcatMaxLifetime is the hard cap — a listener never outlives the
	// engagement's tolerance for open ports.
	netcatDefaultLifetime = 300 * time.Second
	netcatMaxLifetime     = 900 * time.Second
	// netcatOutputCap caps the captured data returned to the model (8 KB,
	// like the other tools).
	netcatOutputCap = 8192
)

// Netcat arms a local TCP listener (ncat) to receive shells or data from an
// in-scope target, in the same stateful two-call shape as exec: an 'arm'
// call starts the listener and a later 'collect' call returns what it has
// captured. The listener binds locally only — it never initiates target
// traffic — so the scope gate applies to 'source', the host expected to
// connect (e.g. the box a reverse shell was fired from); the local bind port
// is not a target and is not gated. One listener at a time: a new arm kills
// the previous one.
type Netcat struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	capture string
	port    int
	live    bool
	armed   bool // an arm has happened in this run (stays true after the listener stops)
}

func (*Netcat) Name() string   { return "netcat" }
func (*Netcat) Mutating() bool { return true }

func (*Netcat) Description() string {
	return "Local TCP listener (ncat) for receiving shells or data from an in-scope target. " +
		"Two calls: action=arm (default) starts the listener on 'port' (default 4444, lifetime 'timeout' seconds, default 300, max 900) " +
		"and returns the harness's local IP to use as the payload's LHOST; action=collect returns what the listener captured (8 KB cap). " +
		"Pass 'source', the in-scope host expected to connect — it is scope-gated. The local bind port is not target traffic and is not gated. " +
		"Arm the listener BEFORE firing the payload that connects to it; a new arm replaces the previous listener."
}

func (*Netcat) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"action":  map[string]any{"type": "string", "description": `"arm" (default) to start the listener, "collect" to read captured data`},
			"source":  map[string]any{"type": "string", "description": "In-scope host expected to connect to the listener (scope-gated); required for arm"},
			"port":    map[string]any{"type": "integer", "description": "Local TCP port to listen on (default 4444, 1-65535)"},
			"timeout": map[string]any{"type": "integer", "description": "Listener lifetime in seconds (default 300, max 900)"},
		},
	}
}

func (n *Netcat) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	switch action := strArg(args, "action"); action {
	case "collect":
		return n.collect()
	case "", "arm":
		return n.arm(ctx, s, args)
	default:
		return core.Result{Tool: "netcat", Allowed: false, Reason: "action must be 'arm' or 'collect'"}
	}
}

func (n *Netcat) arm(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	source := strArg(args, "source")
	if source == "" {
		return core.Result{Tool: "netcat", Allowed: false, Reason: "missing required argument 'source' (the in-scope host expected to connect)"}
	}
	// Gate the expected connecting host. The listener itself only binds a
	// local port — that is not target traffic, so no port is checked.
	ok, reason := s.CheckTarget(ctx, source, nil)
	if !ok {
		return core.Result{Tool: "netcat", Target: source, Allowed: false, Reason: reason}
	}
	port := intArg(args, "port", netcatDefaultPort)
	if port < 1 || port > 65535 {
		return core.Result{Tool: "netcat", Target: source, Allowed: false, Reason: fmt.Sprintf("port %d out of range 1-65535", port)}
	}
	lifetime := time.Duration(intArg(args, "timeout", int(netcatDefaultLifetime/time.Second))) * time.Second
	if lifetime > netcatMaxLifetime {
		lifetime = netcatMaxLifetime
	}
	if _, err := exec.LookPath("ncat"); err != nil {
		return core.Result{Tool: "netcat", Target: source, Allowed: true,
			Reason: "ncat is not installed in this environment; listener capture is unavailable",
		}
	}
	// Fail fast on a busy port rather than arming a listener that cannot bind.
	probe, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return core.Result{Tool: "netcat", Target: source, Allowed: false,
			Reason: fmt.Sprintf("port %d is not free on the harness: %v", port, err),
		}
	}
	probe.Close()

	capture := filepath.Join(os.TempDir(), fmt.Sprintf("mole-ncat-%d-%s.cap", port, randomHex(4)))
	cmd := exec.Command("ncat", "-4", "-l", "-p", strconv.Itoa(port), "-k", "-o", capture)

	n.mu.Lock()
	defer n.mu.Unlock()
	n.stopLocked()
	if n.capture != "" {
		os.Remove(n.capture)
	}
	if err := cmd.Start(); err != nil {
		return core.Result{Tool: "netcat", Target: source, Allowed: true, Reason: fmt.Sprintf("start ncat: %v", err)}
	}
	n.cmd = cmd
	n.capture = capture
	n.port = port
	n.live = true
	n.armed = true
	// Reap the listener and note its exit; the lifetime timer kills it.
	go func() {
		cmd.Wait()
		n.mu.Lock()
		n.live = false
		n.mu.Unlock()
	}()
	time.AfterFunc(lifetime, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.stopLocked()
	})

	pl := map[string]any{
		"armed":    true,
		"port":     port,
		"lifetime": lifetime.String(),
		"capture":  capture,
		"hint":     "use the lhost and this port as LHOST/LPORT in the payload",
	}
	if ip := harnessLocalIP(); ip != "" {
		pl["lhost"] = ip
	}
	return core.Result{Tool: "netcat", Target: source, Allowed: true, Payload: pl}
}

func (n *Netcat) collect() core.Result {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.armed {
		return core.Result{Tool: "netcat", Allowed: false, Reason: "no listener armed — call netcat with action=arm first"}
	}
	data, err := os.ReadFile(n.capture)
	pl := map[string]any{
		"armed": n.live,
		"port":  n.port,
		"bytes": len(data),
	}
	if !n.live {
		pl["status"] = "listener exited (lifetime reached, replaced, or ncat stopped)"
	}
	if err != nil {
		pl["data"] = ""
		pl["status"] = fmt.Sprintf("no captured data (%v)", err)
	} else {
		if len(data) > netcatOutputCap {
			data = data[:netcatOutputCap]
		}
		pl["data"] = string(data)
	}
	return core.Result{Tool: "netcat", Allowed: true, Payload: pl}
}

// stopLocked kills the armed listener. Callers hold n.mu. The capture path
// is kept so collect can still return what arrived after the listener stops.
func (n *Netcat) stopLocked() {
	if n.cmd != nil && n.cmd.Process != nil {
		n.cmd.Process.Kill()
	}
	n.cmd = nil
	n.live = false
}

// harnessLocalIP best-effort reports the harness's egress IP (the address a
// target's connecting shell would see) by UDP-dialing a public address; no
// packet is sent. Empty when no route exists.
func harnessLocalIP() string {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "0000"
	}
	return hex.EncodeToString(b)
}
