package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	core "github.com/cubyte-nl/agent-core/tools"

	"mole/internal/scope"
)

const (
	ffufRate       = 10               // req/s, baked in: prompt rules are not guarantees
	ffufTimeout    = 15 * time.Minute // whole-run bound, like nuclei
	maxFfufEntries = 5000             // raw wordlist entries probed per run
	maxFfufHits    = 50               // hits handed to the model
)

// defaultFfufExtensions are appended to each extensionless wordlist entry.
const defaultFfufExtensions = "php,asp,aspx,jsp"

// ffufMatchCodes are the status codes that mark an interesting path: live
// pages, redirects, and access-denied (a 401/403 on a hidden admin path is
// signal — the path exists).
const ffufMatchCodes = "200,301,302,307,308,401,403,500"

// builtinFfufPaths is the curated first-pass directory wordlist used when no
// wordlist file is given. Chosen for signal: the paths where admin panels,
// API/docs, config and source leakage, backups, and common CMS installs
// live. Entries that contain a dot are full filenames and are probed as-is.
var builtinFfufPaths = []string{
	// admin panels & consoles
	"admin", "admin/", "administrator", "admin/login", "admin/index",
	"admincp", "admin-panel", "adminpanel", "controlpanel", "cp", "console",
	"dashboard", "login", "signin", "sign-in", "manager", "management",
	"wp-admin", "wp-login.php", "administrator.php", "phpmyadmin", "pma",
	"mysql", "dbadmin", "solr", "solr/admin/cores", "jenkins", "grafana",
	"kibana", "prometheus", "zabbix", "nagios", "webmail", "owa", "zimbra",
	"roundcube", "nextcloud", "owncloud", "portainer", "harbor", "sonarqube",
	"jira", "confluence", "gitlab", "gitea", "git", "nexus", "artifactory",
	"airflow", "hue", "hadoop", "spark", "yarn", "elastic", "elasticsearch",
	// API & docs
	"api", "api/", "api/v1", "api/v2", "docs", "swagger", "swagger.json",
	"swagger-ui.html", "openapi.json", "openapi.yaml", "redoc", "graphql",
	"graphiql", "v2", "v3",
	// config & source leakage
	".git", ".git/config", ".git/HEAD", ".svn", ".hg", ".env", ".env.local",
	".env.production", "web.config", "config", "config.php", "settings.json",
	"package.json", "composer.json", "robots.txt", "sitemap.xml",
	"crossdomain.xml",
	// backups & stale tiers
	"backup", "backups", "archive", "old", "old/", "dev", "test", "staging",
	"tmp", "temp", "upload", "uploads", "files",
	// CMS paths
	"wp-content", "wp-includes", "wp-json", "wp-cron.php", "xmlrpc.php",
	"drupal", "node", "joomla", "index.php", "main", "home",
	// Spring/infra endpoints
	"actuator", "actuator/health", "actuator/env", "actuator/mappings",
	"actuator/beans", "actuator/configprops", "actuator/threaddump",
	"actuator/heapdump", "actuator/logfile", "env", "metrics", "status",
	"health", "debug", "trace", "info",
}

// Ffuf runs rate-limited directory/content fuzzing (ffuf) against an
// in-scope web target. This is an opt-in active tool: it probes candidate
// paths (admin panels, API/docs, config and source leakage, backups, CMS
// paths) and sends real requests to the target. The rate limit and the
// wordlist/hit caps are baked in, not left to the model.
type Ffuf struct{}

func (Ffuf) Name() string   { return "ffuf" }
func (Ffuf) Mutating() bool { return true }

func (Ffuf) Description() string {
	return "Directory/content fuzzing (ffuf) against an in-scope web URL: probes candidate paths " +
		"(admin panels, API/docs, config & source leakage like .git/.env/web.config, backups, CMS paths) " +
		"and reports the paths that respond. Vulnerability scanning: active probing, rate limited to " +
		"10 req/s, wordlist capped at 5000 entries, results capped at 50 hits. Uses a built-in curated " +
		"wordlist by default; pass extensions or a local wordlist file for a targeted run."
}

func (Ffuf) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "In-scope web target, e.g. https://host or https://host/app (fuzzing runs under this path).",
			},
			"extensions": map[string]any{
				"type":        "string",
				"description": `Optional comma-separated file extensions to try per path, e.g. "php,asp". Entries that already contain a dot are not expanded. Defaults to "php,asp,aspx,jsp".`,
			},
			"wordlist": map[string]any{
				"type":        "string",
				"description": "Optional path to a local wordlist file, one candidate path per line. Defaults to the built-in curated list.",
			},
		},
		"required": []any{"url"},
	}
}

func (Ffuf) Run(ctx context.Context, s *scope.Scope, args map[string]any) core.Result {
	urlStr := strArg(args, "url")
	if urlStr == "" {
		return core.Result{Tool: "ffuf", Allowed: false, Reason: "missing required argument 'url'"}
	}
	parsed, host, port, err := parseProbeURL(urlStr)
	if err != nil {
		return core.Result{Tool: "ffuf", Target: urlStr, Allowed: false, Reason: fmt.Sprintf("invalid URL: %v", err)}
	}
	ok, reason := s.CheckTarget(ctx, host, &port)
	if !ok {
		return core.Result{Tool: "ffuf", Target: host, Allowed: false, Reason: reason}
	}
	if _, err := exec.LookPath("ffuf"); err != nil {
		return core.Result{Tool: "ffuf", Target: host, Allowed: true,
			Reason: "ffuf is not installed in this environment; directory fuzzing is unavailable"}
	}

	entries, err := ffufEntries(strArg(args, "wordlist"))
	if err != nil {
		return core.Result{Tool: "ffuf", Target: host, Allowed: true, Reason: "wordlist: " + err.Error()}
	}
	paths := expandFfufPaths(entries, ffufExtensions(strArg(args, "extensions")))
	if len(paths) == 0 {
		return core.Result{Tool: "ffuf", Target: host, Allowed: true, Reason: "no paths to probe"}
	}

	// The expanded list and the JSON output go to temp files; ffuf reads the
	// wordlist from disk and writes hits to the file (stdout stays quiet).
	wl, err := os.CreateTemp("", "mole-ffuf-wordlist-*.txt")
	if err != nil {
		return core.Result{Tool: "ffuf", Target: host, Allowed: true, Reason: "wordlist: " + err.Error()}
	}
	defer os.Remove(wl.Name())
	if _, err := wl.WriteString(strings.Join(paths, "\n") + "\n"); err != nil {
		wl.Close()
		return core.Result{Tool: "ffuf", Target: host, Allowed: true, Reason: "wordlist: " + err.Error()}
	}
	wl.Close()
	jsonOut, err := os.CreateTemp("", "mole-ffuf-output-*.json")
	if err != nil {
		return core.Result{Tool: "ffuf", Target: host, Allowed: true, Reason: "output file: " + err.Error()}
	}
	defer os.Remove(jsonOut.Name())
	jsonOut.Close()

	base := parsed.Scheme + "://" + parsed.Host + parsed.Path
	cmdArgs := []string{
		"-u", base + "/FFUF",
		"-w", wl.Name(),
		"-rate", strconv.Itoa(ffufRate),
		"-t", "10",
		"-mc", ffufMatchCodes,
		"-of", "json",
		"-o", jsonOut.Name(),
		"-noninteractive",
	}
	res := runExternal(ctx, "ffuf", "ffuf", host, cmdArgs, ffufTimeout)
	raw, _ := os.ReadFile(jsonOut.Name())
	if p, ok := res.Payload.(map[string]any); ok {
		p["probed"] = len(paths)
		// stdout is ffuf's progress noise; the hits live in the JSON file.
		p["output"] = trimFfufOutput(string(raw))
	}
	return res
}

// ffufEntries returns the raw wordlist entries: the lines of a local wordlist
// file (comments, blanks and unparseable lines skipped), capped at
// maxFfufEntries, or the built-in list when no file is given.
func ffufEntries(wordlistPath string) ([]string, error) {
	if wordlistPath == "" {
		return builtinFfufPaths, nil
	}
	raw, err := os.ReadFile(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", wordlistPath, err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		e := strings.TrimSpace(strings.TrimPrefix(line, "/"))
		if e == "" || strings.HasPrefix(e, "#") || strings.ContainsAny(e, " \t") {
			continue
		}
		out = append(out, e)
		if len(out) >= maxFfufEntries {
			break
		}
	}
	return out, nil
}

// ffufExtensions parses the optional extensions argument (comma-separated,
// lower-cased, "." stripped) and falls back to the common web-app extensions.
func ffufExtensions(arg string) []string {
	if strings.TrimSpace(arg) == "" {
		return strings.Split(defaultFfufExtensions, ",")
	}
	var out []string
	for _, e := range strings.Split(arg, ",") {
		e = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(e, ".")))
		if e != "" && !strings.ContainsAny(e, "/\\ ") {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return strings.Split(defaultFfufExtensions, ",")
	}
	return out
}

// expandFfufPaths expands the raw wordlist entries into the concrete paths to
// probe: each extension is appended to every entry that does not already
// contain a dot (a full filename like ".git" or "wp-login.php" is probed
// as-is). The extensionless entry itself is always probed.
func expandFfufPaths(entries []string, extensions []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, e := range entries {
		add(e)
		if strings.Contains(e, ".") {
			continue
		}
		for _, ext := range extensions {
			add(e + "." + ext)
		}
	}
	return out
}

// trimFfufOutput converts ffuf's JSON output into one line per hit,
// "[status] /path (length=N)"; the input map carries the substituted FFUF
// keyword. Non-JSON output (errors, empty runs) passes through trimmed. Hits
// are capped at maxFfufHits, with a note about the dropped ones.
func trimFfufOutput(raw string) string {
	var doc struct {
		Results []struct {
			Input  map[string]any `json:"input"`
			Status int            `json:"status"`
			Length int            `json:"length"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return strings.TrimSpace(raw)
	}
	lines := make([]string, 0, len(doc.Results))
	for _, r := range doc.Results {
		path, _ := r.Input["FFUF"].(string)
		lines = append(lines, fmt.Sprintf("[%d] /%s (length=%d)", r.Status, path, r.Length))
	}
	if len(lines) > maxFfufHits {
		lines = append([]string{fmt.Sprintf("… %d additional hit(s) trimmed; re-run with a narrower wordlist for the full list",
			len(lines)-maxFfufHits)}, lines[:maxFfufHits]...)
	}
	return strings.Join(lines, "\n")
}
