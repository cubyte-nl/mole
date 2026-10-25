// Package knowledge is MOLE's mini-RAG: it indexes the technique docs
// (chunked by markdown heading) — the per-service enumeration checklists,
// and the post-foothold playbook in exploit-in-scope engagements — and
// returns the sections most relevant to a query, so the model can consult
// them at the moment it needs it (the knowledge_search tool) instead of
// carrying the full text in the system prompt.
//
// Retrieval is deterministic and dependency-free: query and chunks are
// tokenised, and chunks are ranked by weighted keyword overlap — a heading or
// doc-title hit weighs three times a body hit, and consecutive query terms
// both present in a chunk earn a phrase bonus. At the size of this corpus
// (tens of chunks, a few dozen KB) that is as reliable as embeddings and far
// easier to debug. The scorer is isolated behind Search so an
// embedding-based one can replace it later without touching the tool or the
// prompt.
package knowledge

import (
	"fmt"
	"sort"
	"strings"
)

// Doc is one knowledge document: Name is the source label shown in search
// results, Content its markdown text.
type Doc struct {
	Name    string
	Content string
}

// Chunk is one retrievable section of a doc: where it came from, the heading
// path below the doc title, and the section text.
type Chunk struct {
	Source  string // e.g. "linux-windows-basics.md"
	Title   string // the doc's # title
	Heading string // heading path, e.g. "Linux > Permissions"
	Body    string // the section's text
}

// indexed is a chunk with its token sets precomputed at build time.
type indexed struct {
	Chunk
	head map[string]bool // tokens of the heading path plus the doc title
	body map[string]bool
}

// Store is an in-memory index over the knowledge docs, built once per run.
// Nothing is persisted.
type Store struct {
	chunks []indexed
}

// New indexes the docs in the given order. Order matters: it is the
// deterministic tie-break for equal scores.
func New(docs []Doc) *Store {
	s := &Store{}
	for _, d := range docs {
		for _, ch := range chunkDoc(d) {
			head := map[string]bool{}
			for _, t := range tokens(ch.Heading + " " + ch.Title) {
				head[t] = true
			}
			body := map[string]bool{}
			for _, t := range tokens(ch.Body) {
				body[t] = true
			}
			s.chunks = append(s.chunks, indexed{Chunk: ch, head: head, body: body})
		}
	}
	return s
}

// Chunks returns the indexed sections in doc order (for debugging and tests;
// retrieval goes through Search).
func (s *Store) Chunks() []Chunk {
	out := make([]Chunk, 0, len(s.chunks))
	for i := range s.chunks {
		out = append(out, s.chunks[i].Chunk)
	}
	return out
}

// Search returns up to k chunks most relevant to the query, best first.
// Chunks with no token overlap at all are dropped, so an irrelevant query
// yields an empty result rather than noise.
func (s *Store) Search(query string, k int) []Chunk {
	if k <= 0 {
		k = 4
	}
	q := tokens(query)
	if len(q) == 0 {
		return nil
	}
	type hit struct {
		i  int
		sc float64
	}
	var hits []hit
	for i := range s.chunks {
		if sc := score(&s.chunks[i], q); sc > 0 {
			hits = append(hits, hit{i, sc})
		}
	}
	sort.SliceStable(hits, func(a, b int) bool { return hits[a].sc > hits[b].sc })
	if len(hits) > k {
		hits = hits[:k]
	}
	out := make([]Chunk, 0, len(hits))
	for _, h := range hits {
		out = append(out, s.chunks[h.i].Chunk)
	}
	return out
}

// maxChunkBody caps how much of one section a search result carries: enough
// to act on, and the corpus will grow (issue #5 and beyond), so keep the
// model's context bounded.
const maxChunkBody = 1600

// Render formats search hits for a tool result: each hit is labelled with its
// source doc and section, so the model can cite it in findings and the
// report.
func Render(chunks []Chunk) string {
	var b strings.Builder
	for i, c := range chunks {
		body := c.Body
		if len(body) > maxChunkBody {
			body = body[:maxChunkBody] + "…"
		}
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "[%d] %s — %s\n%s", i+1, c.Source, c.Heading, body)
	}
	return b.String()
}

// chunkDoc splits a doc into chunks at ## and ### headings. The # title
// becomes the Title context of every chunk; the heading path (## plus ###)
// becomes the Heading. Text before the first ## and sections with no body of
// their own (content living entirely in ### children) are dropped: the docs
// are authored so knowledge lives under headings.
func chunkDoc(d Doc) []Chunk {
	title := ""
	h2, h3 := "", ""
	var body []string
	var out []Chunk
	flush := func() {
		text := strings.TrimSpace(strings.Join(body, "\n"))
		body = nil
		heading := h2
		if h3 != "" {
			heading = h2 + " > " + h3
		}
		if text == "" || heading == "" {
			return
		}
		out = append(out, Chunk{Source: d.Name, Title: title, Heading: heading, Body: text})
	}
	for _, line := range strings.Split(d.Content, "\n") {
		switch {
		case title == "" && strings.HasPrefix(line, "# "):
			title = strings.TrimSpace(strings.TrimPrefix(line, "# "))
		case strings.HasPrefix(line, "### "):
			flush()
			h3 = strings.TrimSpace(strings.TrimPrefix(line, "### "))
		case strings.HasPrefix(line, "## "):
			flush()
			h2 = strings.TrimSpace(strings.TrimPrefix(line, "## "))
			h3 = ""
		default:
			if h2 != "" {
				body = append(body, line)
			}
		}
	}
	flush()
	return out
}

// stopwords are the words that carry no topical signal in this corpus.
var stopwords = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
	"be": true, "but": true, "by": true, "can": true, "did": true, "do": true,
	"does": true, "for": true, "from": true, "had": true, "has": true,
	"have": true, "how": true, "if": true, "in": true, "into": true, "is": true,
	"it": true, "its": true, "may": true, "might": true, "no": true, "not": true,
	"of": true, "on": true, "or": true, "per": true, "should": true, "so": true,
	"than": true, "that": true, "the": true, "their": true, "then": true,
	"this": true, "to": true, "was": true, "were": true, "what": true,
	"when": true, "where": true, "which": true, "who": true, "will": true,
	"with": true, "would": true, "you": true, "your": true,
}

// tokens lowercases, splits on non-alphanumerics, drops stopwords and
// single letters, and strips a light plural so "services" matches "service".
// The "ss" suffix is protected so tokens like lsass, ps and ss survive.
func tokens(s string) []string {
	var out []string
	var cur strings.Builder
	add := func() {
		t := cur.String()
		cur.Reset()
		if len(t) == 1 || stopwords[t] {
			return
		}
		if len(t) > 3 && strings.HasSuffix(t, "s") && !strings.HasSuffix(t, "ss") {
			t = t[:len(t)-1]
		}
		out = append(out, t)
	}
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			cur.WriteRune(r)
		} else {
			add()
		}
	}
	add()
	return out
}

// score ranks one chunk against the query tokens: heading/title hits weigh
// three times body hits, and each pair of consecutive query terms both
// present in the chunk earns a phrase bonus.
func score(c *indexed, q []string) float64 {
	var sc float64
	for _, t := range q {
		if c.head[t] {
			sc += 3
		}
		if c.body[t] {
			sc += 1
		}
	}
	for i := 0; i+1 < len(q); i++ {
		a, b := q[i], q[i+1]
		if (c.head[a] || c.body[a]) && (c.head[b] || c.body[b]) {
			sc += 2
		}
	}
	return sc
}
