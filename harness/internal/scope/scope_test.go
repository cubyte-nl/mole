package scope

import (
	"context"
	"testing"
)

var ctx = context.Background()

func confirmed(basis string) Authorization {
	return Authorization{Basis: basis, Operator: "t", Date: "2026-10-06", Confirmed: true}
}

func mustValidate(t *testing.T, s *Scope) *Scope {
	t.Helper()
	if err := s.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return s
}

func TestCheckTargetCIDR(t *testing.T) {
	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"10.0.0.0/8"}, Auth: confirmed(BasisOwnInfra)})
	if ok, _ := s.CheckTarget(ctx, "10.1.2.3", nil); !ok {
		t.Error("10.1.2.3 should be in scope")
	}
	if ok, reason := s.CheckTarget(ctx, "8.8.8.8", nil); ok {
		t.Errorf("8.8.8.8 should be denied, got: %s", reason)
	}
}

func TestCheckTargetOutOfScopeWins(t *testing.T) {
	s := mustValidate(t, &Scope{
		Name:       "e",
		InScope:    []string{"127.0.0.1", "10.0.0.0/8"},
		OutOfScope: []string{"10.1.2.3"},
		Auth:       confirmed(BasisCTFLab),
	})
	ok, reason := s.CheckTarget(ctx, "10.1.2.3", nil)
	if ok {
		t.Fatalf("10.1.2.3 should be denied: %s", reason)
	}
	if reason == "" {
		t.Error("denial should carry a reason")
	}
}

func TestCheckTargetNameResolvingToInScopeIP(t *testing.T) {
	s := mustValidate(t, &Scope{
		Name:       "e",
		InScope:    []string{"127.0.0.1"},
		OutOfScope: []string{"example.org"},
		Auth:       confirmed(BasisCTFLab),
	})
	if ok, _ := s.CheckTarget(ctx, "localhost", nil); !ok {
		t.Error("localhost resolves to 127.0.0.1 and should be in scope")
	}
	if ok, reason := s.CheckTarget(ctx, "example.org", nil); ok {
		t.Errorf("example.org is explicitly out of scope, got: %s", reason)
	}
	if ok, _ := s.CheckTarget(ctx, "8.8.8.8", nil); ok {
		t.Error("8.8.8.8 is not in the in-scope list")
	}
}

func TestCheckTargetUnresolvableFailsClosed(t *testing.T) {
	s := mustValidate(t, &Scope{Name: "e", InScope: []string{"127.0.0.1"}, Auth: confirmed(BasisCTFLab)})
	ok, reason := s.CheckTarget(ctx, "definitely-not-a-host.invalid", nil)
	if ok {
		t.Fatalf("unresolvable host must be denied, got: %s", reason)
	}
}

func TestCheckTargetPorts(t *testing.T) {
	s := mustValidate(t, &Scope{
		Name:    "e",
		InScope: []string{"127.0.0.1"},
		Ports:   []int{80, 443},
		Auth:    confirmed(BasisOwnInfra),
	})
	p80, p8080 := 80, 8080
	if ok, _ := s.CheckTarget(ctx, "127.0.0.1", &p80); !ok {
		t.Error("port 80 should be allowed")
	}
	if ok, reason := s.CheckTarget(ctx, "127.0.0.1", &p8080); ok {
		t.Errorf("port 8080 should be denied, got: %s", reason)
	}
}

func TestCheckTargetStripsSchemaAndPort(t *testing.T) {
	s := mustValidate(t, &Scope{
		Name:    "e",
		InScope: []string{"127.0.0.1"},
		Ports:   []int{8080},
		Auth:    confirmed(BasisOwnInfra),
	})
	if ok, reason := s.CheckTarget(ctx, "http://localhost:8080/foo", nil); !ok {
		t.Errorf("http://localhost:8080/foo should reduce to an in-scope target, got: %s", reason)
	}
}

func TestValidateUnconfirmed(t *testing.T) {
	s := &Scope{Name: "e", InScope: []string{"127.0.0.1"},
		Auth: Authorization{Basis: BasisOwnInfra, Operator: "t", Confirmed: false}}
	if err := s.Validate(); err == nil {
		t.Error("unconfirmed scope must not validate")
	}
}

func TestValidateEmptyScope(t *testing.T) {
	s := &Scope{Name: "e", Auth: confirmed(BasisOwnInfra)}
	if err := s.Validate(); err == nil {
		t.Error("empty in-scope list must not validate")
	}
}

func TestMatchName(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"example.internal", "example.internal", true},
		{"a.b.example.internal", "example.internal", true},
		{"badexample.internal", "example.internal", false},
		{"EXAMPLE.INTERNAL.", "example.internal", true},
		{"10.0.0.1", "10.0.0.1/8", false}, // CIDRs are not name patterns
	}
	for _, c := range cases {
		if got := matchName(c.host, []string{c.pattern}); got != c.want {
			t.Errorf("matchName(%q, %q) = %v, want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestMatchAddr(t *testing.T) {
	cases := []struct {
		addr, pattern string
		want          bool
	}{
		{"10.1.2.3", "10.0.0.0/8", true},
		{"10.1.2.3", "10.1.2.3", true},
		{"10.1.2.3", "10.2.0.0/16", false},
		{"10.1.2.3", "not-an-ip", false},
	}
	for _, c := range cases {
		if got := matchAddr(c.addr, []string{c.pattern}); got != c.want {
			t.Errorf("matchAddr(%q, %q) = %v, want %v", c.addr, c.pattern, got, c.want)
		}
	}
}
