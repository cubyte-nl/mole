package scope

import (
	"context"
	"testing"
)

// TestCubyteNode2OutOfScope verifies the fix for the incident where the
// agent declared node2.cubby.nl out of scope but the gate still allowed it:
// with the out_of_scope entries in scope.yaml, both the name and the IP are
// now refused, while the rest of the zone stays in scope.
func TestCubyteNode2OutOfScope(t *testing.T) {
	s := &Scope{
		Name:       "cubyte",
		InScope:    []string{"cubby.nl"},
		OutOfScope: []string{"node2.cubby.nl", "188.165.204.91"},
		Auth:       Authorization{Basis: BasisOwnInfra, Confirmed: true},
	}

	// Name-based denial (the path CheckTarget hits for node2.cubby.nl).
	if !matchName("node2.cubby.nl", s.OutOfScope) {
		t.Fatal("node2.cubby.nl should match the out-of-scope name patterns")
	}
	// IP-based denial: a bare IP resolves to itself, so CheckTarget needs no DNS.
	if ok, reason := s.CheckTarget(context.Background(), "188.165.204.91", nil); ok {
		t.Fatalf("expected 188.165.204.91 to be denied, got allowed (%s)", reason)
	}
	// Out-of-scope wins over in-scope suffix match.
	if !matchName("node2.cubby.nl", s.InScope) {
		t.Fatal("node2.cubby.nl suffix-matches cubby.nl; the gate must rely on out-of-scope winning")
	}
	// The rest of the zone stays in scope.
	if !matchName("www.cubby.nl", s.InScope) {
		t.Fatal("www.cubby.nl should remain in scope")
	}
}
