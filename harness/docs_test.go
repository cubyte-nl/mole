package main

import (
	"strings"
	"testing"

	"github.com/cubyte-nl/agent-core/knowledge"
)

// kbForTest mirrors main.go's doc loading: the always-loaded docs plus the
// vulnerability-scanning docs, under the same names the agent sees in
// knowledge_search results.
func kbForTest() *knowledge.Store {
	return knowledge.New([]knowledge.Doc{
		{Name: "service-enumeration.md", Content: serviceEnumeration},
		{Name: "light-scripting.md", Content: lightScripting},
		{Name: "linux-windows-basics.md", Content: linuxWindowsBasics},
		{Name: "privilege-escalation.md", Content: privEscalation},
		{Name: "web-bugs.md", Content: webBugs},
	})
}

// TestIssue15SectionsAreRetrievable locks in that the issue #15 technique
// sections answer the natural queries the agent would fire for them: the top
// hit for each query must be the section that covers it.
func TestIssue15SectionsAreRetrievable(t *testing.T) {
	kb := kbForTest()
	cases := []struct {
		query string
		want  string
	}{
		{"sqli file access load_file outfile", "SQLi impact: schema scope and file access"},
		{"sql injection other databases tables information_schema", "SQLi impact: schema scope and file access"},
		{"credential reuse harvested database login", "Credential reuse"},
		{"setup.php reset database install endpoint", "Setup and install endpoints"},
	}
	for _, c := range cases {
		hits := kb.Search(c.query, 4)
		if len(hits) == 0 {
			t.Errorf("query %q: no hits at all", c.query)
			continue
		}
		if hits[0].Heading != c.want {
			t.Errorf("query %q: top hit %q (from %s), want %q", c.query, hits[0].Heading, hits[0].Source, c.want)
		}
	}
}

// TestIssue16SectionsAreRetrievable locks in that the issue #16 technique
// sections answer the natural queries the agent would fire for them: the top
// hit for each query must be the section that covers it.
func TestIssue16SectionsAreRetrievable(t *testing.T) {
	kb := kbForTest()
	cases := []struct {
		query string
		want  string
	}{
		{"container escape privileged capabilities", "Linux > Container escape"},
		{"kernel version local exploit", "Linux > Escalation order (checklist)"},
		{"reachable database credentials lateral movement", "Lateral movement and adjacent hosts"},
		{"mysql udf plugin file privilege", "Databases (MySQL, PostgreSQL, MSSQL, MongoDB, Redis)"},
	}
	for _, c := range cases {
		hits := kb.Search(c.query, 4)
		if len(hits) == 0 {
			t.Errorf("query %q: no hits at all", c.query)
			continue
		}
		if hits[0].Heading != c.want {
			t.Errorf("query %q: top hit %q (from %s), want %q", c.query, hits[0].Heading, hits[0].Source, c.want)
		}
	}
}

// TestDocsAreTargetAgnostic guards the corpus against target-specific
// references: the technique docs are served to the model in every engagement,
// so they must not name any particular test application.
func TestDocsAreTargetAgnostic(t *testing.T) {
	docs := []struct {
		name    string
		content string
	}{
		{"service-enumeration.md", serviceEnumeration},
		{"light-scripting.md", lightScripting},
		{"linux-windows-basics.md", linuxWindowsBasics},
		{"privilege-escalation.md", privEscalation},
		{"web-bugs.md", webBugs},
	}
	for _, d := range docs {
		if i := strings.Index(strings.ToLower(d.content), "dvwa"); i >= 0 {
			t.Errorf("%s: target-specific reference at byte offset %d", d.name, i)
		}
	}
}
