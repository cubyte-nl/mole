package tools

import (
	"strings"
	"testing"

	"mole/internal/knowledge"
)

// fixtureKB is a minimal stand-in for the embedded post-foothold playbook.
const fixtureKB = `# Test playbook

## Linux

### Permissions

- setuid-root binaries are the classic local escalation.

## Windows

### Where credentials live

- lsass.exe holds logged-on credentials.
`

// newKB builds a knowledge store over the fixture, for registry and tool
// tests that do not care about the corpus content itself.
func newKB() *knowledge.Store {
	return knowledge.New([]knowledge.Doc{{Name: "fixture.md", Content: fixtureKB}})
}

// knowledge_search is registered in every engagement: the per-service
// enumeration checklists guide reconnaissance as much as the post-foothold
// playbook guides exploitation.
func TestKnowledgeSearchAlwaysRegistered(t *testing.T) {
	if !registered(NewRegistry(true, newLedger(t), newKB()), "knowledge_search") {
		t.Error("knowledge_search missing from an exploit-in-scope registry")
	}
	if !registered(NewRegistry(false, newLedger(t), newKB()), "knowledge_search") {
		t.Error("knowledge_search missing from a reconnaissance registry")
	}
	// A reconnaissance registry must still refuse vuln-scanning tools at run
	// time.
	res := NewRegistry(false, newLedger(t), newKB()).Run(testCtx, testScope("127.0.0.1"),
		"nuclei", `{"url":"http://127.0.0.1/"}`)
	if res.Allowed {
		t.Error("nuclei reachable in a reconnaissance registry")
	}
}

func TestKnowledgeSearchTool(t *testing.T) {
	s := testScope("127.0.0.1")
	tool := KnowledgeSearch{K: newKB()}

	// A missing query is denied up front.
	if res := tool.Run(testCtx, s, map[string]any{}); res.Allowed {
		t.Error("missing query was allowed")
	}

	// A relevant query returns the matching section, labelled with its
	// source doc and heading so the model can cite it.
	res := tool.Run(testCtx, s, map[string]any{"query": "lsass credentials"})
	if !res.Allowed {
		t.Fatalf("knowledge_search denied: %s", res.Reason)
	}
	payload, _ := res.Payload.(string)
	for _, needle := range []string{"fixture.md", "Where credentials live", "lsass.exe"} {
		if !strings.Contains(payload, needle) {
			t.Errorf("payload missing %q:\n%s", needle, payload)
		}
	}

	// A query with no overlap degrades to a hint, not an error.
	res = tool.Run(testCtx, s, map[string]any{"query": "zzzq xyzzy"})
	if !res.Allowed {
		t.Fatalf("no-match search denied: %s", res.Reason)
	}
	if res.Reason != "no matching sections" {
		t.Errorf("no-match reason = %q", res.Reason)
	}
}
