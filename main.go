// Command mole is a starting point for running the MOLE harness end to end:
// it builds the Docker image (only when the build context changed — the
// image carries a context-version label, and an up-to-date image is reused
// after a quick confirm), asks for the LLM environment and persists it to a
// config file, asks for an objective, checks (and offers to change) the
// engagement's vulnerability-scanning state, then runs the container and streams
// (tails) its output to the terminal.
//
// Usage:
//
//	mole                         full interactive flow
//	mole -no-build               skip the image build
//	mole -objective "..."        skip the objective prompt
//	mole -dry-run                print the docker run command, don't execute
//
// The MOLE harness itself lives in the harness/ subdirectory; reports and
// scope files live in engagement/ (gitignored data).
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultImage  = "mole"
	defaultConfig = "launcher.env"
	appDir        = "harness" // subdirectory holding the MOLE Dockerfile/context
	versionLabel  = "mole.version"
)

// Config is the launcher's persistent state, stored as KEY=VALUE lines in a
// .env-style file (launcher.env by default). Values that map 1:1 onto the
// MOLE_LLM_* environment variables keep that name in the file so the config
// is self-documenting.
type Config struct {
	Image      string
	BaseURL    string
	APIKey     string
	Model      string
	Engagement string
	MaxSteps   int
}

// configKeys is the write order for the config file.
var configKeys = []string{
	"MOLE_IMAGE",
	"MOLE_LLM_BASE_URL",
	"MOLE_LLM_API_KEY",
	"MOLE_LLM_MODEL",
	"MOLE_ENGAGEMENT",
	"MOLE_MAX_STEPS",
}

func (c *Config) values() map[string]string {
	return map[string]string{
		"MOLE_IMAGE":        c.Image,
		"MOLE_LLM_BASE_URL": c.BaseURL,
		"MOLE_LLM_API_KEY":  c.APIKey,
		"MOLE_LLM_MODEL":    c.Model,
		"MOLE_ENGAGEMENT":   c.Engagement,
		"MOLE_MAX_STEPS":    strconv.Itoa(c.MaxSteps),
	}
}

func (c *Config) apply(key, value string) {
	switch key {
	case "MOLE_IMAGE":
		c.Image = value
	case "MOLE_LLM_BASE_URL":
		c.BaseURL = value
	case "MOLE_LLM_API_KEY":
		c.APIKey = value
	case "MOLE_LLM_MODEL":
		c.Model = value
	case "MOLE_ENGAGEMENT":
		c.Engagement = value
	case "MOLE_MAX_STEPS":
		if n, err := strconv.Atoi(value); err == nil {
			c.MaxSteps = n
		}
	}
}

// loadConfig reads KEY=VALUE lines from path. A missing file yields a
// zero-value config, not an error, so the first run just uses defaults.
func loadConfig(path string) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		c.apply(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	return c, nil
}

// saveConfig writes the config file with mode 0600 (it may hold an API key).
func saveConfig(path string, c *Config) error {
	var sb strings.Builder
	sb.WriteString("# MOLE launcher configuration.\n")
	sb.WriteString("# Written by `mole`; safe to edit by hand.\n")
	for _, k := range configKeys {
		fmt.Fprintf(&sb, "%s=%s\n", k, c.values()[k])
	}
	return os.WriteFile(path, []byte(sb.String()), 0o600)
}

// ---------- interactive helpers ----------

// readLine reads one line; a final line without a newline (EOF) is still
// returned as long as it has content.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if line == "" && err != nil {
		return "", err
	}
	return line, nil
}

// ask prints a prompt and reads one line; an empty answer keeps the default.
func ask(r *bufio.Reader, label, def string) (string, error) {
	suffix := ""
	if def != "" {
		suffix = " [" + def + "]"
	}
	fmt.Printf("  %-22s %s: ", label, suffix)
	line, err := readLine(r)
	if err != nil {
		if def == "" {
			return "", err
		}
		return def, nil
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

func step(n, total int, title string) {
	fmt.Printf("\n[%d/%d] %s\n", n, total, title)
}

// runStream executes a command with its output streamed to the terminal
// (i.e. "tails" it). In dry-run mode it only prints the command line.
func runStream(name string, args []string, dry bool) error {
	if dry {
		fmt.Println("  $ " + name + " " + displayArgs(args))
		return nil
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("%s exited with code %d", name, ee.ExitCode())
		}
		return err
	}
	return nil
}

// displayArgs renders args for the dry-run printout, quoting any value that
// contains spaces so the line reads like a real shell command.
func displayArgs(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " \t") {
			parts[i] = strconv.Quote(a)
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}

// ---------- image versioning ----------

// contextVersion fingerprints everything `docker build` would see for the
// context in dir (the files it sends, respecting .dockerignore), plus the
// Dockerfile and .dockerignore themselves (they steer the build even though
// .dockerignore keeps them out of the context). Same content yields the same
// 12-hex version, so a different version means a new image is worth
// building.
func contextVersion(dir string) (string, error) {
	ignored, err := loadDockerignore(filepath.Join(dir, ".dockerignore"))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if ignored(rel + "/") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if ignored(rel) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s\n", filepath.ToSlash(rel))
		h.Write(b)
		return nil
	})
	if err != nil {
		return "", err
	}
	for _, extra := range []string{"Dockerfile", ".dockerignore"} {
		b, err := os.ReadFile(filepath.Join(dir, extra))
		if err != nil {
			if os.IsNotExist(err) && extra == ".dockerignore" {
				continue
			}
			return "", err
		}
		fmt.Fprintf(h, "%s\n", extra)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12], nil
}

// dockerignoreRule is one .dockerignore line.
type dockerignoreRule struct {
	negate   bool
	dirs     bool // pattern only matches directories (trailing "/")
	anchored bool // leading "/" pins the pattern to the context root
	pat      string
}

// loadDockerignore reads a .dockerignore file and returns a predicate over
// slash-separated relative paths (a trailing "/" marks directories). Rules
// are applied in file order, last match wins, with `!` negation; a path is
// excluded if it or any ancestor directory is excluded.
func loadDockerignore(path string) (func(string) bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return func(string) bool { return false }, nil
		}
		return nil, err
	}
	var rules []dockerignoreRule
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r dockerignoreRule
		if strings.HasPrefix(line, "!") {
			r.negate = true
			line = line[1:]
		}
		if strings.HasPrefix(line, "/") {
			r.anchored = true
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			r.dirs = true
			line = strings.TrimSuffix(line, "/")
		}
		r.pat = line
		rules = append(rules, r)
	}
	// matchEntry reports whether any rule applies to the single entry rel,
	// and (last match winning) whether that resolves to excluded.
	matchEntry := func(rel string) (matched, excluded bool) {
		isDir := strings.HasSuffix(rel, "/")
		base := strings.TrimSuffix(rel, "/")
		name := filepath.Base(base)
		matched, excluded = false, false
		for _, r := range rules {
			var ok bool
			switch {
			case r.anchored:
				ok, _ = filepath.Match(r.pat, base) // pinned to the root
			case strings.Contains(r.pat, "/"):
				ok, _ = filepath.Match(r.pat, base) // relative to the root
			default:
				ok, _ = filepath.Match(r.pat, name) // bare name, any depth
			}
			if !ok || (r.dirs && !isDir) {
				continue
			}
			matched = true
			excluded = !r.negate
		}
		return matched, excluded
	}
	return func(rel string) bool {
		base := strings.TrimSuffix(rel, "/")
		// Check the path itself, then each ancestor directory; the deepest
		// entry any rule touches decides the outcome.
		candidates := []string{rel}
		parts := strings.Split(base, "/")
		for i := len(parts) - 1; i >= 1; i-- {
			candidates = append(candidates, strings.Join(parts[:i], "/")+"/")
		}
		for _, c := range candidates {
			if matched, excluded := matchEntry(c); matched {
				return excluded
			}
		}
		return false
	}, nil
}

// imageState reports what is known about a local image: whether it exists
// and, if so, the mole.version label it carries ("" = unlabeled, e.g. an
// image built before versioning existed). An unlabeled image is treated as
// stale: one rebuild stamps the label and ends the one-off rebuild.
type imageState struct {
	exists  bool
	version string
}

func imageInfo(image string) imageState {
	out, err := exec.Command("docker", "image", "inspect",
		"--format", fmt.Sprintf("{{index .Config.Labels %q}}", versionLabel), image).Output()
	if err != nil {
		return imageState{}
	}
	v := strings.TrimSpace(string(out))
	if v == "" || v == "<no value>" {
		return imageState{exists: true}
	}
	return imageState{exists: true, version: v}
}

// confirm asks a yes/no question; anything that does not start with "y"
// (including an empty line) is a no.
func confirm(r *bufio.Reader, label string) (bool, error) {
	fmt.Printf("  %s [y/N]: ", label)
	line, err := readLine(r)
	if err != nil {
		if err == io.EOF {
			return false, nil
		}
		return false, err
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y"), nil
}

// ---------- the five steps ----------

func buildImage(image, version string, dry bool) error {
	step(1, 5, "Build the Docker image")
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found on PATH")
	}
	return runStream("docker", []string{"build",
		"--label", versionLabel + "=" + version, "-t", image, appDir}, dry)
}

// ensureImage decides whether to (re)build: it fingerprints the build
// context and compares it to the mole.version label of the local image.
// The image is rebuilt only when it is missing or a newer version is
// available; an up-to-date image is reused after the customer confirms.
func ensureImage(r *bufio.Reader, image string, dry bool) error {
	step(1, 5, "Docker image")
	v, err := contextVersion(appDir)
	if err != nil {
		return err
	}
	if dry {
		fmt.Printf("  Context version: %s (dry-run: no image check)\n", v)
		return buildImage(image, v, true)
	}
	st := imageInfo(image)
	switch {
	case !st.exists:
		fmt.Printf("  Image %q not found — building (version %s).\n", image, v)
		return buildImage(image, v, false)
	case st.version == "":
		fmt.Printf("  Image %q has no version label — rebuilding to stamp %s.\n", image, v)
		return buildImage(image, v, false)
	case st.version == v:
		fmt.Printf("  Image %q is up to date (version %s).\n", image, v)
		rebuild, err := confirm(r, "Rebuild anyway")
		if err != nil {
			return err
		}
		if !rebuild {
			fmt.Println("  Using the current image.")
			return nil
		}
		return buildImage(image, v, false)
	default:
		fmt.Printf("  New version available (image %s, context %s) — rebuilding.\n", st.version, v)
		return buildImage(image, v, false)
	}
}

// configure prompts for the LLM environment (prefilled from the existing
// config where present) and writes the config file.
func configure(r *bufio.Reader, path string, c *Config) error {
	step(2, 5, "LLM configuration (press Enter to keep the default)")
	fmt.Printf("  Config file: %s\n", path)
	qs := []struct {
		label string
		value string
		set   func(string)
	}{
		{"LLM base URL", c.BaseURL, func(v string) { c.BaseURL = v }},
		{"LLM API key (optional)", c.APIKey, func(v string) { c.APIKey = v }},
		{"LLM model", c.Model, func(v string) { c.Model = v }},
		{"Engagement (optional)", c.Engagement, func(v string) { c.Engagement = v }},
	}
	for _, q := range qs {
		v, err := ask(r, q.label, q.value)
		if err != nil {
			return err
		}
		q.set(v)
	}
	ms, err := ask(r, "Max steps (0 = default 100)", strconv.Itoa(c.MaxSteps))
	if err != nil {
		return err
	}
	if n, perr := strconv.Atoi(ms); perr == nil {
		c.MaxSteps = n
	}
	if err := saveConfig(path, c); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("  Saved %s\n", path)
	return nil
}

func askObjective(r *bufio.Reader, preset string) (string, error) {
	step(3, 5, "Objective")
	if preset != "" {
		fmt.Printf("  Using: %s\n", preset)
		return preset, nil
	}
	v, err := ask(r, "Prompt", "")
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", fmt.Errorf("an objective is required")
	}
	return v, nil
}

// scopeFile mirrors the persisted fields of harness/internal/scope.Scope, in
// the same field order, so the launcher can read and re-write the
// engagement's scope.yaml without importing the harness module. The launcher
// only ever changes `vuln_scanning`; everything else round-trips unchanged.
type scopeFile struct {
	Name         string     `yaml:"name"`
	InScope      []string   `yaml:"in_scope"`
	OutOfScope   []string   `yaml:"out_of_scope,omitempty"`
	Ports        []int      `yaml:"ports,omitempty"`
	VulnScanning bool       `yaml:"vuln_scanning,omitempty"`
	Auth         authRecord `yaml:"authorisation"`
}

// authRecord mirrors scope.Authorization.
type authRecord struct {
	Basis     string `yaml:"basis"`
	Operator  string `yaml:"operator"`
	Date      string `yaml:"date"`
	Reference string `yaml:"reference,omitempty"`
	Client    string `yaml:"client,omitempty"`
	Confirmed bool   `yaml:"confirmed"`
}

// resolveEngagement determines which engagement's scope.yaml to touch: the
// named one if given, otherwise the single engagement under dir that has a
// scope.yaml.
func resolveEngagement(dir, name string) (string, error) {
	if name != "" {
		return name, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("no engagement found under %s", dir)
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() && fileExists(filepath.Join(dir, e.Name(), "scope.yaml")) {
			found = append(found, e.Name())
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("no engagement found under %s (run the harness init first)", dir)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("multiple engagements under %s (%s); pass -engagement", dir, strings.Join(found, ", "))
	}
}

// askVulnScanning is step 4: it shows the vulnerability-scanning state
// recorded in the engagement's scope.yaml and offers to change it. Enabling is
// opt-in and requires a typed YES, the same authorisation pattern as the init
// wizard. A missing or unreadable scope file is not fatal: the recorded scope
// is kept and the run proceeds.
func askVulnScanning(r *bufio.Reader, dir string, c *Config, dry bool) error {
	step(4, 5, "Vulnerability scanning")
	if dry {
		fmt.Println("  (dry-run: scope.yaml is not modified)")
		return nil
	}
	name, err := resolveEngagement(dir, c.Engagement)
	if err != nil {
		fmt.Printf("  %s — keeping the recorded scope.\n", err)
		return nil
	}
	path := filepath.Join(dir, name, "scope.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("  Cannot read %s: %v — keeping the recorded scope.\n", path, err)
		return nil
	}
	var s scopeFile
	if err := yaml.Unmarshal(raw, &s); err != nil {
		fmt.Printf("  Cannot parse %s: %v — keeping the recorded scope.\n", path, err)
		return nil
	}
	// Backward compatibility: earlier releases named the opt-in "exploit".
	// Honor that key (as scope.Load does) so a recorded opt-in is read, and
	// rewrite it under the canonical vuln_scanning key.
	var legacy struct {
		Exploit bool `yaml:"exploit"`
	}
	if err := yaml.Unmarshal(raw, &legacy); err == nil && legacy.Exploit {
		s.VulnScanning = true
	}
	state := "disabled (reconnaissance only)"
	if s.VulnScanning {
		state = "ENABLED (vulnerability scanning)"
	}
	fmt.Printf("  Engagement %s: vulnerability scanning %s\n", name, state)
	ans, err := ask(r, "Enable vulnerability scanning?", yesNo(s.VulnScanning))
	if err != nil {
		return err
	}
	enable := strings.EqualFold(strings.TrimSpace(ans), "yes")
	if enable == s.VulnScanning {
		fmt.Println("  No change.")
		return nil
	}
	if enable {
		fmt.Println("  I confirm that vulnerability scanning is authorised for the in-scope targets.")
		typed, err := ask(r, "Type YES to confirm", "")
		if err != nil {
			return err
		}
		if strings.TrimSpace(typed) != "YES" {
			fmt.Println("  Not confirmed — vulnerability scanning stays disabled.")
			return nil
		}
	} else {
		ok, err := confirm(r, "Disable vulnerability scanning")
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("  No change.")
			return nil
		}
	}
	s.VulnScanning = enable
	out, err := yaml.Marshal(&s)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return err
	}
	fmt.Printf("  Vulnerability scanning %s — saved to %s\n", yesNo(enable), path)
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// runContainer assembles and runs the `docker run` command for the MOLE
// harness, streaming the container output (tail) to the terminal.
func runContainer(c *Config, engagementDir, network string, addHost bool, objective string, dry bool) error {
	step(5, 5, "Run the container (Ctrl-C to abort)")
	absDir, err := filepath.Abs(engagementDir)
	if err != nil {
		return err
	}
	args := []string{"run", "--rm"}
	if addHost {
		// Lets the container reach a local LLM server on the host.
		args = append(args, "--add-host=host.docker.internal:host-gateway")
	}
	args = append(args,
		"-v", absDir+":/work/engagement",
		"-e", "MOLE_LLM_BASE_URL="+c.BaseURL,
	)
	if c.APIKey != "" {
		args = append(args, "-e", "MOLE_LLM_API_KEY="+c.APIKey)
	}
	args = append(args, "-e", "MOLE_LLM_MODEL="+c.Model)
	if network != "" {
		// E.g. --network host when targets are only reachable on the host LAN.
		args = append(args, "--network", network)
	}
	// Everything after the image name is passed to `mole run` inside the container.
	args = append(args, c.Image, "run")
	if c.Engagement != "" {
		args = append(args, "-e", c.Engagement)
	}
	args = append(args, "-o", objective)
	if c.MaxSteps > 0 {
		args = append(args, "--max-steps", strconv.Itoa(c.MaxSteps))
	}
	if err := runStream("docker", args, dry); err != nil {
		return err
	}
	name := c.Engagement
	if name == "" {
		name = "<engagement>"
	}
	fmt.Printf("\nDone. Report and transcript land in %s/%s/\n", engagementDir, name)
	return nil
}

// ---------- main ----------

func main() {
	var (
		image      = flag.String("image", defaultImage, "Docker image tag")
		config     = flag.String("config", defaultConfig, "config file path")
		engagement = flag.String("engagement", "", "engagement name (empty = infer)")
		dir        = flag.String("dir", "engagement", "engagement directory")
		objective  = flag.String("objective", "", "objective text (skips the prompt)")
		maxSteps   = flag.Int("max-steps", 0, "tool-step budget (0 = harness default)")
		network    = flag.String("network", "", "docker network (e.g. host)")
		noBuild    = flag.Bool("no-build", false, "skip the image build")
		noAddHost  = flag.Bool("no-add-host", false, "do not map host.docker.internal (remote LLM)")
		dryRun     = flag.Bool("dry-run", false, "print the docker run command without executing it")
	)
	flag.Parse()

	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Fprintln(os.Stderr, "mole: docker not found on PATH")
		os.Exit(1)
	}

	fmt.Println("MOLE launcher — build, configure, run")

	cfg, err := loadConfig(*config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mole:", err)
		os.Exit(1)
	}
	if *image != "" {
		cfg.Image = *image
	}
	if cfg.Image == "" {
		cfg.Image = defaultImage
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://host.docker.internal:8080/v1"
	}
	if cfg.Model == "" {
		cfg.Model = "swift-qwen3.8-27b"
	}
	if *engagement != "" {
		cfg.Engagement = *engagement
	}
	if *maxSteps > 0 {
		cfg.MaxSteps = *maxSteps
	}

	r := bufio.NewReader(os.Stdin)

	if !*noBuild {
		if err := ensureImage(r, cfg.Image, *dryRun); err != nil {
			fmt.Fprintln(os.Stderr, "mole:", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("\n[1/5] Build the Docker image — skipped (-no-build)\n")
	}
	if err := configure(r, *config, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "mole:", err)
		os.Exit(1)
	}
	obj, err := askObjective(r, *objective)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mole:", err)
		os.Exit(1)
	}
	if err := askVulnScanning(r, *dir, cfg, *dryRun); err != nil {
		fmt.Fprintln(os.Stderr, "mole:", err)
		os.Exit(1)
	}
	if err := runContainer(cfg, *dir, *network, !*noAddHost, obj, *dryRun); err != nil {
		fmt.Fprintln(os.Stderr, "mole:", err)
		os.Exit(1)
	}
}
