package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

const (
	maxSubdomainNames = 200 // cap on names reported in the payload
	maxWordlistLines  = 20000
	subdomainWorkers  = 25 // concurrent DNS lookups
	subdomainTimeout  = 3 * time.Second
)

// builtinSubdomainLabels are the common labels probed by default when no
// wordlist file is given. Curated for signal: the names that real web tiers,
// SaaS front doors and internal tooling most often live on.
var builtinSubdomainLabels = []string{
	// web front doors
	"www", "web", "www1", "www2", "webmail", "web1", "portal", "portal1",
	"intranet", "extranet", "app", "apps", "store", "stores", "shop", "shop1",
	"cart", "checkout", "blog", "wiki", "news", "events", "docs", "documents",
	// mail
	"mail", "mail1", "mail2", "smtp", "smtp1", "relay", "relay1", "pop", "pop3",
	"imap", "autodiscover", "outlook", "owa", "exchange",
	// app / environment tiers
	"api", "api1", "api2", "dev", "dev1", "staging", "stage", "test", "qa",
	"beta", "alpha", "uat", "pre", "preview", "sandbox", "demo", "lab", "labs",
	"internal", "partner", "partners", "client", "clients", "customer",
	"customers", "member", "members", "community", "mobile", "m",
	// auth / identity
	"sso", "sso1", "auth", "login", "signin", "account", "accounts", "iam",
	"keycloak", "okta", "oidc", "identity",
	// data & storage
	"db", "db1", "database", "databases", "sql", "mysql", "postgres", "mongo",
	"mongodb", "redis", "kafka", "rabbitmq", "queue", "queues", "storage",
	"blob", "s3", "archive", "archives", "backup", "backups", "backup1",
	"restore", "vault", "vault1", "secrets", "data", "dwh", "analytics", "bi",
	"metrics",
	// infra & ops
	"admin", "admin1", "ops", "ops1", "noc", "soc", "bastion", "bastion1",
	"jump", "jumpbox", "dmz", "dmz1", "server", "servers", "node", "nodes",
	"node1", "node2", "k8s", "kubernetes", "cluster", "clusters", "git",
	"github", "gitlab", "gitea", "jenkins", "ci", "cd", "build", "builds",
	"drone", "argo", "harbor", "registry", "docker", "devops", "release",
	"releases", "artifacts", "deploy", "deploys",
	// monitoring & logging
	"status", "status1", "monitor", "monitoring", "grafana", "kibana",
	"kibana1", "prometheus", "jaeger", "zabbix", "nagios", "uptime", "ping",
	"health", "healthcheck", "logs", "logging", "syslog", "audit",
	"compliance",
	// media / CDN
	"cdn", "cdn1", "static", "assets", "asset", "img", "images", "media",
	"files", "file", "video", "videos", "live", "stream", "streams", "radio",
	"podcast", "podcasts", "tv",
	// collaboration & comms
	"chat", "chat1", "support", "help", "helpdesk", "help1", "kb", "knowledge",
	"zendesk", "crm", "erp", "hr", "payroll", "office", "office365", "o365",
	"teams", "sharepoint", "drive", "dropbox", "slack", "zoom", "meeting",
	"meetings", "webex", "call", "calls", "phone", "phones", "voice", "sip",
	"pbx", "voip",
	// edge & misc
	"iot", "iot1", "home", "homeassistant", "hass", "nas", "plex", "plex1",
	"print", "printer", "printers", "scan", "scanner", "scans", "vpn", "vpn1",
	"vpn2", "proxy", "proxy1", "ws", "ws1", "wss", "graphql", "grpc", "cloud",
	"cloud1", "saas", "tenant", "tenants",
	// security
	"security", "sec", "siem", "ids", "ids1", "waf", "firewall", "fw", "pentest",
}

// Subdomains enumerates subdomains of an in-scope domain by resolving
// candidate names against the domain's own nameservers. There is no
// third-party service: the only traffic is DNS to the target itself (the
// same class of traffic dns_lookup sends), and a wildcard probe detects and
// filters wildcard zones.
type Subdomains struct{}

func (Subdomains) Name() string   { return "subdomains" }
func (Subdomains) Mutating() bool { return false }

func (Subdomains) Description() string {
	return "Subdomain enumeration for an in-scope domain: candidate names (a built-in list of common names, or a local wordlist file) are resolved against the domain's own nameservers. Active DNS only, no third-party services; wildcard zones are detected and filtered."
}

func (Subdomains) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"domain":   map[string]any{"type": "string", "description": "In-scope domain to enumerate subdomains of"},
			"wordlist": map[string]any{"type": "string", "description": "Optional path to a local wordlist file, one candidate name per line (labels, or full names ending in the domain). Defaults to the built-in list of common names."},
		},
		"required": []any{"domain"},
	}
}

func (Subdomains) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	domain := strings.ToLower(strings.TrimSuffix(strArg(args, "domain"), "."))
	if domain == "" {
		return core.Result{Tool: "subdomains", Allowed: false, Reason: "missing required argument 'domain'"}
	}
	ok, reason := s.CheckTarget(ctx, domain, nil)
	if !ok {
		return core.Result{Tool: "subdomains", Target: domain, Allowed: false, Reason: reason}
	}

	candidates, err := candidateNames(domain, strArg(args, "wordlist"))
	if err != nil {
		return core.Result{Tool: "subdomains", Target: domain, Allowed: true, Reason: "wordlist: " + err.Error()}
	}
	if len(candidates) == 0 {
		return core.Result{Tool: "subdomains", Target: domain, Allowed: true, Reason: "no candidate names to probe"}
	}

	// Wildcard probe first: if a random label resolves, the zone is
	// wildcarded and matching address sets are filtered out below.
	wildcard, wildAddrs := false, []string(nil)
	cctx, cancel := context.WithTimeout(ctx, subdomainTimeout)
	if addrs, err := s.Resolve(cctx, randomLabel(domain)); err == nil {
		wildcard, wildAddrs = true, addrs
	}
	cancel()

	// Resolve the candidates with bounded concurrency.
	found := make(map[string][]string, len(candidates))
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string, len(candidates))
	for i := 0; i < subdomainWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				cctx, cancel := context.WithTimeout(ctx, subdomainTimeout)
				addrs, err := s.Resolve(cctx, name)
				cancel()
				if err != nil {
					continue // NXDOMAIN / timeout: not a live name
				}
				mu.Lock()
				found[name] = addrs
				mu.Unlock()
			}
		}()
	}
	for _, c := range candidates {
		jobs <- c
	}
	close(jobs)
	wg.Wait()

	var names []string
	addresses := make(map[string][]string, len(found))
	for name, addrs := range found {
		if wildcard && sameAddrSet(addrs, wildAddrs) {
			continue // matches the wildcard zone, not a real record
		}
		// Belt and braces: the name must match the recorded in-scope patterns.
		if !s.NameInScope(name) {
			continue
		}
		names = append(names, name)
		addresses[name] = addrs
	}
	sort.Strings(names)
	total := len(names)
	truncated := false
	if len(names) > maxSubdomainNames {
		names = names[:maxSubdomainNames]
		truncated = true
	}
	return core.Result{Tool: "subdomains", Target: domain, Allowed: true,
		Payload: map[string]any{
			"domain":    domain,
			"count":     total,
			"names":     names,
			"addresses": addresses,
			"wildcard":  wildcard,
			"probed":    len(candidates),
			"truncated": truncated,
		}}
}

// candidateNames builds the list of names to resolve for domain. A wordlist
// file gives one candidate per line: a label is prefixed with the domain, a
// line that is (or ends in) the domain is used as-is. Without a file the
// built-in label list is used. The apex domain itself is always included.
func candidateNames(domain, wordlistPath string) ([]string, error) {
	seen := map[string]bool{domain: true}
	out := []string{domain}
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if wordlistPath == "" {
		for _, l := range builtinSubdomainLabels {
			add(l + "." + domain)
		}
		return out, nil
	}
	raw, err := os.ReadFile(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", wordlistPath, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		name := strings.ToLower(strings.TrimSpace(line))
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		name = strings.TrimPrefix(name, "*.")
		if name == "" || !isValidName(name) {
			continue
		}
		if name != domain && !strings.HasSuffix(name, "."+domain) {
			name = name + "." + domain
		}
		add(name)
		if len(out) > maxWordlistLines {
			break
		}
	}
	return out, nil
}

func isValidName(name string) bool {
	if len(name) > 253 {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '.':
		default:
			return false
		}
	}
	return !strings.HasPrefix(name, "-") && !strings.HasPrefix(name, ".")
}

// randomLabel returns a name that (with overwhelming probability) does not
// exist, used to detect wildcard zones.
func randomLabel(domain string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "mzn" + hex.EncodeToString(b) + "." + domain
}

// sameAddrSet reports whether two address lists carry the same addresses.
func sameAddrSet(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, x := range a {
		seen[x] = true
	}
	for _, y := range b {
		if !seen[y] {
			return false
		}
	}
	return true
}
