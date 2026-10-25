package knowledge

import (
	"reflect"
	"strings"
	"testing"
)

// fixture mirrors the structure of the real playbook: a # title, intro text
// that must not become a chunk, ## sections with no body of their own
// (content lives in ### children), and ### sections carrying knowledge.
const fixture = `# Test playbook

Intro line that must not become a chunk.

## Linux

### Permissions

- setuid-root binaries are the classic local escalation.
- Check ACLs before dismissing a file.

### Cron

- Cron spool files under /var/spool/cron; writable entries escalate.

## Windows

### Services

- Unquoted service path escalation via a writable prefix directory.

### Where credentials live

- lsass.exe holds logged-on credentials; kerberos tickets move you.
`

func newFixtureStore() *Store {
	return New([]Doc{{Name: "fixture.md", Content: fixture}})
}

func TestChunkDocByHeading(t *testing.T) {
	chunks := newFixtureStore().Chunks()
	if len(chunks) != 4 {
		t.Fatalf("got %d chunks, want 4: %+v", len(chunks), chunks)
	}
	if chunks[0].Source != "fixture.md" || chunks[0].Title != "Test playbook" {
		t.Errorf("chunk identity = %+v, want source fixture.md / title Test playbook", chunks[0])
	}
	wantHeadings := []string{
		"Linux > Permissions",
		"Linux > Cron",
		"Windows > Services",
		"Windows > Where credentials live",
	}
	for i, want := range wantHeadings {
		if chunks[i].Heading != want {
			t.Errorf("chunk %d heading = %q, want %q", i, chunks[i].Heading, want)
		}
	}
	for _, c := range chunks {
		if strings.Contains(c.Body, "Intro line") {
			t.Errorf("pre-heading intro text leaked into chunk %q", c.Heading)
		}
	}
}

func TestSearchRanksRelevantSectionFirst(t *testing.T) {
	s := newFixtureStore()
	cases := []struct {
		query string
		want  string
	}{
		{"setuid binary", "Linux > Permissions"},
		{"writable cron spool", "Linux > Cron"},
		{"unquoted service path", "Windows > Services"},
		{"lsass credentials", "Windows > Where credentials live"},
		{"kerberos ticket", "Windows > Where credentials live"},
	}
	for _, tc := range cases {
		hits := s.Search(tc.query, 3)
		if len(hits) == 0 {
			t.Errorf("query %q: no hits", tc.query)
			continue
		}
		if hits[0].Heading != tc.want {
			got := make([]string, len(hits))
			for i, h := range hits {
				got[i] = h.Heading
			}
			t.Errorf("query %q: top hit = %q, want %q (all: %v)", tc.query, hits[0].Heading, tc.want, got)
		}
	}
}

func TestSearchNoMatch(t *testing.T) {
	if hits := newFixtureStore().Search("zzzq xyzzy", 3); len(hits) != 0 {
		t.Errorf("irrelevant query returned %d hits, want 0", len(hits))
	}
	if hits := newFixtureStore().Search("the and of", 3); len(hits) != 0 {
		t.Errorf("stopword-only query returned hits: %+v", hits)
	}
}

func TestSearchRespectsKAndIsStable(t *testing.T) {
	s := newFixtureStore()
	if hits := s.Search("setuid cron service lsass", 1); len(hits) != 1 {
		t.Fatalf("k=1 returned %d hits, want 1", len(hits))
	}
	a := s.Search("setuid cron service lsass", 4)
	b := s.Search("setuid cron service lsass", 4)
	if !reflect.DeepEqual(a, b) {
		t.Error("identical queries returned different orderings")
	}
}

func TestRenderLabelsSourceAndHeading(t *testing.T) {
	hits := newFixtureStore().Search("lsass", 2)
	out := Render(hits)
	for _, needle := range []string{"fixture.md", "Where credentials live", "lsass.exe", "[1]"} {
		if !strings.Contains(out, needle) {
			t.Errorf("rendered output missing %q:\n%s", needle, out)
		}
	}
}
