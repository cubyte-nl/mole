package tools

import (
	"context"
	"fmt"

	"github.com/cubyte-nl/agent-core/knowledge"
	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

// KnowledgeSearch retrieves technique knowledge (the per-service enumeration
// checklists, and the post-foothold Linux & Windows playbook for
// exploit-in-scope engagements) from harness/docs. It is a local tool — it
// reads the embedded knowledge base and never touches a target — and is
// always registered.
type KnowledgeSearch struct {
	K *knowledge.Store
}

func (KnowledgeSearch) Name() string   { return "knowledge_search" }
func (KnowledgeSearch) Mutating() bool { return false }

func (KnowledgeSearch) Description() string {
	return "Search the loaded technique knowledge by keyword: the per-service enumeration checklists " +
		"(what to check on web/HTTP, SSH, RDP, database, Samba and SMTP services) and, in " +
		"exploit-in-scope engagements, the post-foothold Linux & Windows playbook and the " +
		"privilege-escalation checklist (Linux sudo/SUID/cron, Windows tokens and stored credentials). " +
		"Use it with a specific query — 'web enumeration', 'ssh service', 'actuator', 'sudo nopasswd', " +
		"'setuid escalation', 'token abuse', 'lsass', 'exec vector registration', 'no markers in the response' — " +
		"when a service is discovered or a foothold lands, " +
		"and act on the sections it returns."
}

func (KnowledgeSearch) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"query": map[string]any{
				"type":        "string",
				"description": "What you need to know, e.g. 'setuid binary escalation', 'lsass credentials', 'unquoted service path'.",
			},
		},
		"required": []string{"query"},
	}
}

// maxHits caps how many sections one search returns: enough to act on, not
// the whole doc.
const maxHits = 4

func (t KnowledgeSearch) Run(_ context.Context, _ *scope.Scope, args map[string]any) core.Result {
	q := strArg(args, "query")
	if q == "" {
		return core.Result{Tool: "knowledge_search", Allowed: false,
			Reason: "missing required argument: query"}
	}
	hits := t.K.Search(q, maxHits)
	if len(hits) == 0 {
		return core.Result{Tool: "knowledge_search", Allowed: true,
			Reason:  "no matching sections",
			Payload: "No sections matched that query. Try a more specific term — a command, a file path, or a vector name (setuid, lsass, cron, unquoted path)."}
	}
	return core.Result{
		Tool:    "knowledge_search",
		Allowed: true,
		Reason:  fmt.Sprintf("%d section(s) matched", len(hits)),
		Payload: knowledge.Render(hits),
	}
}
