// Package tools holds the capability plumbing shared by every agent: the
// boundary interface, the structured Result, the Tool interface, and the
// Registry that exposes tools to the model. Every tool asks the boundary
// before it touches a target; a denied target is reported back and never acted
// on.
//
// The registry is generic over the agent's boundary type B so each agent keeps
// its own fully-typed boundary (collie's scope with CheckHost/CheckCluster,
// mole's scope with CheckTarget, ...) while sharing this plumbing. The loop
// only ever needs Describe from the boundary; the real checks happen inside
// each tool's Run.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cubyte-nl/agent-core/llm"
)

// Boundary is the minimum the shared loop needs from an agent's boundary: a
// human-readable description for the system prompt and report. Concrete tools
// take the agent's real boundary type (which does the actual target checks).
type Boundary interface {
	Describe() string
}

// Result is the structured outcome of a tool run, fed back to the LLM.
type Result struct {
	Tool    string `json:"tool"`
	Target  string `json:"target,omitempty"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"` // boundary denial or execution error
	Payload any    `json:"result,omitempty"`
}

// Tool is a single agent capability over boundary type B. Mutating reports
// whether the tool can change the target; the registry only exposes mutating
// tools when the agent is allowed to make changes.
type Tool[B Boundary] interface {
	Name() string
	Description() string
	Parameters() map[string]any
	Mutating() bool
	Run(ctx context.Context, b B, args map[string]any) Result
}

// Registry holds the tools available to the agent.
type Registry[B Boundary] struct {
	order  []string
	byName map[string]Tool[B]
}

// NewRegistry builds a registry from the given tools, dropping mutating tools
// unless mutate is true. A read-only agent cannot reach a mutating tool even
// if the model asks for it.
func NewRegistry[B Boundary](mutate bool, all ...Tool[B]) *Registry[B] {
	r := &Registry[B]{byName: make(map[string]Tool[B], len(all))}
	for _, tl := range all {
		if tl.Mutating() && !mutate {
			continue
		}
		r.byName[tl.Name()] = tl
		r.order = append(r.order, tl.Name())
	}
	return r
}

// IsMutating reports whether a registered tool mutates its target.
func (r *Registry[B]) IsMutating(name string) bool {
	if tl, ok := r.byName[name]; ok {
		return tl.Mutating()
	}
	return false
}

// Specs renders the tools as function-call specs for the LLM.
func (r *Registry[B]) Specs() []llm.ToolSpec {
	specs := make([]llm.ToolSpec, 0, len(r.order))
	for _, n := range r.order {
		tl := r.byName[n]
		specs = append(specs, llm.ToolSpec{
			Type: "function",
			Function: llm.FunctionSpec{
				Name:        tl.Name(),
				Description: tl.Description(),
				Parameters:  tl.Parameters(),
			},
		})
	}
	return specs
}

// Run executes a tool by name. It is the only path by which the agent invokes
// tools; the boundary inside each tool is authoritative. Malformed arguments
// are reported back to the model rather than causing a crash.
func (r *Registry[B]) Run(ctx context.Context, b B, name, rawArgs string) Result {
	tl, ok := r.byName[name]
	if !ok {
		return Result{Tool: name, Allowed: false, Reason: fmt.Sprintf("unknown tool %q", name)}
	}
	var args map[string]any
	if strings.TrimSpace(rawArgs) != "" {
		if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
			return Result{Tool: name, Allowed: false, Reason: fmt.Sprintf("invalid JSON arguments: %v", err)}
		}
	}
	return tl.Run(ctx, b, args)
}

// StrArg reads a trimmed string argument, or "" if absent.
func StrArg(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// IntArg reads an integer argument (accepting JSON number or string), or def.
func IntArg(args map[string]any, key string, def int) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case string:
			if i, err := strconv.Atoi(n); err == nil {
				return i
			}
		}
	}
	return def
}
