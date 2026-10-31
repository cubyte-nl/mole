// Usage:
//
//	mole init                          interactive scoping; writes engagement/<name>/scope.yaml
//	mole run [-e name] [-o objective]  run the LLM-driven agent for an engagement
//	mole check [-e name] HOST [-p N]   ask the scope gate about a target
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cubyte-nl/agent-core/knowledge"
	"github.com/cubyte-nl/agent-core/llm"
	"mole/internal/agent"
	"mole/internal/ledger"
	"mole/internal/scope"
	"mole/internal/tools"
	"mole/internal/wizard"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mole:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	switch args[0] {
	case "init":
		return cmdInit(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "check":
		return cmdCheck(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Print(`mole — scope-gated, LLM-driven security reconnaissance

Usage:
  mole init                          interactive scoping wizard
  mole run [-e engagement] [-o text] run the agent for an engagement
  mole check [-e engagement] HOST    ask the scope gate about a target

Flags for run:
  -e, --engagement NAME  engagement to use (default: the only one)
  -o, --objective TEXT   what the agent should find out
  --max-steps N          tool-step budget (default 100, or MOLE_MAX_STEPS)
  -d, --dir DIR          engagement directory (default "engagement")

Flags for check:
  -p, --port N           port to check
  -d, --dir DIR          engagement directory

Environment:
  MOLE_LLM_BASE_URL    base URL of an OpenAI-compatible endpoint (required for run)
  MOLE_LLM_API_KEY     API key (optional)
  MOLE_LLM_MODEL       model name (required for run)
`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("d", "engagement", "engagement directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("init takes no arguments")
	}
	_, err := wizard.Run(*dir)
	return err
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	name := fs.String("e", "", "engagement name")
	dir := fs.String("d", "engagement", "engagement directory")
	objective := fs.String("o", "", "objective")
	maxSteps := fs.Int("max-steps", envInt("MOLE_MAX_STEPS", 100), "tool-step budget")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("run takes no positional arguments")
	}
	s, path, err := resolveScope(*dir, *name)
	if err != nil {
		return err
	}
	mode := "reconnaissance only"
	if s.VulnScanning {
		mode = "reconnaissance + vulnerability scanning"
	}
	fmt.Printf("Engagement: %s (scope: %s, %s)\n\n", s.Name, path, mode)
	client, err := llm.New("MOLE")
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The findings ledger is the agent's working memory: persisted next to
	// scope.yaml so a resumed engagement keeps its findings.
	led, err := ledger.New(filepath.Join(filepath.Dir(path), "ledger.json"))
	if err != nil {
		return err
	}
	// Technique knowledge, embedded in the binary: chunked and indexed once,
	// served through the knowledge_search tool (always registered). The
	// per-service enumeration checklists and the light-scripting guide apply
	// to every engagement; the post-foothold playbook, the
	// privilege-escalation checklist and the core web-bug playbook ship only
	// when vulnerability scanning / exploitation is in scope.
	var kbDocs []knowledge.Doc
	kbDocs = append(kbDocs,
		knowledge.Doc{Name: "service-enumeration.md", Content: serviceEnumeration},
		knowledge.Doc{Name: "light-scripting.md", Content: lightScripting})
	if s.VulnScanning {
		kbDocs = append(kbDocs,
			knowledge.Doc{Name: "linux-windows-basics.md", Content: linuxWindowsBasics},
			knowledge.Doc{Name: "privilege-escalation.md", Content: privEscalation},
			knowledge.Doc{Name: "web-bugs.md", Content: webBugs})
	}
	kb := knowledge.New(kbDocs)
	reg := tools.NewRegistry(s.VulnScanning, led, kb)
	res, err := agent.Run(ctx, s, client, reg, agent.Config{
		MaxSteps:  *maxSteps,
		Objective: *objective,
		ReportDir: filepath.Dir(path),
		Ledger:    led,
		Out:       func(line string) { fmt.Println(line) },
	})
	if err != nil {
		return err
	}
	fmt.Printf("\nDone: %d tool step(s). Report: %s\n", res.Steps, res.ReportPath)
	return nil
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	name := fs.String("e", "", "engagement name")
	dir := fs.String("d", "engagement", "engagement directory")
	port := fs.Int("p", 0, "port to check")
	// Allow the host before or after flags (flag parsing stops at the first
	// non-flag argument, so move it to the end first).
	args = movePositionalToEnd(args, []string{"-e", "--engagement", "-d", "--dir", "-p", "--port"})
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: mole check [-e engagement] HOST [-p PORT]")
	}
	s, _, err := resolveScope(*dir, *name)
	if err != nil {
		return err
	}
	host := fs.Arg(0)
	var p *int
	if *port != 0 {
		p = port
	}
	ok, reason := s.CheckTarget(context.Background(), host, p)
	verdict := "ALLOWED"
	if !ok {
		verdict = "DENIED"
	}
	fmt.Printf("%s: %s (%s)\n", host, verdict, reason)
	if !ok {
		return fmt.Errorf("denied")
	}
	return nil
}

// loadScopeWithExclusions loads a scope file and wires in its sidecar
// exclusions.yaml (if any), so both mole run and mole check honour runtime
// exclusions recorded by the agent.
func loadScopeWithExclusions(path string) (*scope.Scope, error) {
	s, err := scope.Load(path)
	if err != nil {
		return nil, err
	}
	if err := s.LoadExclusions(filepath.Join(filepath.Dir(path), "exclusions.yaml")); err != nil {
		return nil, err
	}
	return s, nil
}

func resolveScope(dir, name string) (*scope.Scope, string, error) {
	if name != "" {
		path := filepath.Join(dir, name, "scope.yaml")
		s, err := loadScopeWithExclusions(path)
		if err != nil {
			return nil, path, err
		}
		return s, path, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, "", fmt.Errorf("no engagement directory %q; run 'mole init'", dir)
	}
	var found []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name(), "scope.yaml")
		if _, err := os.Stat(p); err == nil {
			found = append(found, p)
		}
	}
	if len(found) == 0 {
		return nil, "", fmt.Errorf("no engagements in %q; run 'mole init'", dir)
	}
	if len(found) > 1 {
		list := strings.TrimPrefix(strings.Join(found, "\n  "), dir+string(filepath.Separator))
		return nil, "", fmt.Errorf("multiple engagements; pick one with -e:\n  %s", list)
	}
	s, err := loadScopeWithExclusions(found[0])
	if err != nil {
		return nil, found[0], err
	}
	return s, found[0], nil
}

// movePositionalToEnd moves the first positional argument to the end so the
// host may appear before flags. valueFlags are flags whose next argument is
// a value, not a positional.
func movePositionalToEnd(args, valueFlags []string) []string {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		isValue := false
		if i > 0 {
			for _, vf := range valueFlags {
				if args[i-1] == vf {
					isValue = true
				}
			}
		}
		if isValue {
			continue
		}
		out := make([]string, 0, len(args))
		out = append(out, args[:i]...)
		out = append(out, args[i+1:]...)
		return append(out, a)
	}
	return args
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
