# MOLE — Modular Offensive Learning Engine

A scope-gated, LLM-driven security reconnaissance harness. MOLE points an
external LLM at a recorded, authorised scope and lets the model plan and
execute reconnaissance — DNS lookups, port scans, service detection, HTTP
probes, TLS certificate inspection, subdomain enumeration — behind a
single hard rule: nothing runs against a target that falls outside that scope.

## Principle: authorisation first

MOLE is built for authorised security testing only — your own infrastructure,
a client engagement with a signed statement of work, or a deliberately
vulnerable lab/CTF environment. The authorisation basis is the first thing the
tool asks for, and it is enforced on every action:

- **Startup scoping.** `mole init` runs an interactive wizard that asks
  targeted questions and writes a binding `engagement/<name>/scope.yaml`:
  in-scope hosts/CIDRs, explicit out-of-scope entries, allowed ports, the
  authorisation basis, the operator, and a typed confirmation. Without that
  confirmation, nothing runs.
- **The scope gate.** Every tool calls the gate *before* touching a target,
  server-side, in the harness itself. A host is resolved to its addresses;
  anything matching the out-of-scope list is denied, and only hosts matching
  the in-scope list are allowed. The gate fails closed — on any doubt (e.g. a
  name that will not resolve), the answer is no.
- **The model cannot bypass the gate.** The LLM acts only through tool calls
  (function calling). Each call is validated and executed by the harness, not
  by the model. A gate denial is returned to the model as the tool result,
  and the rules tell it that a denial is final.
- **Authorisation on record.** The basis (own infra / client engagement +
  reference / CTF lab) is stamped onto every report — which is what a proper
  pentest report requires anyway.

## How a run works

1. `mole init` → binding `engagement/<name>/scope.yaml`.
2. `mole run` → the agent loop:
   - the system prompt carries the authorisation header, the full scope, and
     the recon-only rules;
   - the model calls tools (`dns_lookup`, `nmap`, `http_probe`, `tls_probe`, `tcp_probe`, `security_headers`, `subdomains`, `knowledge_search`, `shell`);
   - every call passes the scope gate before execution;
   - results (including denials) are fed back to the model;
   - a step budget bounds the run; on the model's final answer, a markdown
     report with the authorisation header is written to
     `engagement/<name>/report-YYYYMMDD-HHMMSS.md`, alongside a JSONL
     `transcript-YYYYMMDD-HHMMSS.jsonl` — the full audit trail: system
     prompt, every tool call, every gate denial, and the evidence the model
     saw.

## Build

Paths in this README are relative to the `harness/` directory (the project
root holds the `mole` launcher front-end and the `engagement/` data directory).

```sh
go build -o mole .
```

Requires Go 1.27+ (module: `mole`, one external dependency:
`gopkg.in/yaml.v3`). `nmap` is optional; if it is missing, the tool reports
that port scanning is unavailable instead of failing. `nuclei` and `ffuf`
are likewise optional (vulnerability scanning only) and degrade the same
way when absent. `web_check`, `http_request` and `exec` are stdlib-only and
always available in vulnerability-scanning mode. `shell` is stdlib-only too
(it runs the local `bash`); the container image additionally ships
`python3` and `requests` for script-based exploit adaptation.

## Container

The container is the intended way to run recon: it bundles the harness with
`nmap`, `bash` and `python3` (the `shell` tool's local scripting runtime,
with `requests`), and the opt-in vuln-scanning tooling (`nuclei` and
`ffuf`); it keeps
the tooling off the host, and makes runs reproducible. The LLM stays outside
the container.

```sh
# From the project root (the Dockerfile and context live in harness/):
docker build --ssh default -t mole ./harness

# From the project root (engagement dir mounted, local LLM on the host):
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "$PWD/engagement:/work/engagement" \
  -e MOLE_LLM_BASE_URL=http://host.docker.internal:8080/v1 \
  -e MOLE_LLM_MODEL=swift-qwen3.8-27b \
  mole run -e cubyte --max-steps 15 \
  -o "Map the web tier of the engagement."
```

Notes:
- `--add-host=host.docker.internal:host-gateway` lets the container reach a
  local LLM on the host. For a remote endpoint, set `MOLE_LLM_BASE_URL` to
  its address instead.
- Scanning targets on the host's LAN requires the container to reach them
  (bridge network by default; use `--network host` if the target is only
  reachable on the host network).
- Reports land in the mounted `engagement/<name>/` directory on the host.

## Using the LLM

The model runs entirely outside the harness, at any OpenAI-compatible
chat-completions endpoint (OpenAI, a local llama.cpp server, an ollama proxy,
…):

```sh
export MOLE_LLM_BASE_URL=https://api.openai.com/v1   # required for run
export MOLE_LLM_API_KEY=sk-...                       # optional
export MOLE_LLM_MODEL=gpt-4o                         # required for run
```

## Commands

```sh
mole init                          # interactive scoping wizard
mole run [-e engagement] [-o text] # run the agent for an engagement
mole check [-e engagement] HOST    # ask the scope gate about a target
                                     #   (-p PORT to check a specific port)
```

`-e` selects the engagement; with a single engagement it is inferred. The
`check` command exits non-zero on denial, so it is scriptable.

## Guardrails

- The gate is authoritative and fails closed; out-of-scope always wins.
- Reconnaissance by default: the system prompt forbids exploitation, fuzzing,
  DoS, exfiltration, and changes to systems. (It is a prompt, not a guarantee —
  the gate is the guarantee, and the registry only exposes vulnerability-
  scanning tools when the engagement opted in; `subdomains` sends active DNS queries to
  the target's own nameservers only, with no third-party services involved.)
- `shell` (local scripting) is available in **every** mode and is
  deliberately not gated as mutating: the script runs in the harness, not on
  the target, so it cannot change target state by itself. The risk of a script
  reaching beyond the scope is mitigated by the prompt rules (in-scope
  targets only, minimal and non-destructive scripts) and the transcript audit
  — the full script text is the tool-call argument and is recorded verbatim.
- A tool-step budget (`--max-steps`, default 100) bounds autonomous runs; when
  it is exhausted the model is asked to write its final report from the
  evidence gathered so far.
- `Ctrl-C` aborts the run cleanly (context cancellation propagates to every
  in-flight tool).
- Every run is auditable: the JSONL transcript in the engagement directory
  records the model's reasoning, tool calls, and gate denials.

## Findings ledger

Findings are not left to the model's context memory. Every significant result
is recorded in the engagement's findings ledger (`ledger.json`, written
alongside `scope.yaml`) via `record_finding`, and the ledger is re-injected
into the model's context every turn — so early recon never falls out of
salience, and every later action can cite the finding that motivated it. When
a finding is acted on, `update_finding` advances its lifecycle status
(`new` → `investigated` → `exploited`, or `dropped`) and records the
exploitation link, so the final report renders the finding → exploitation
chain from structured data. The transcript's start event records the ledger
path, and each turn's ledger snapshot is logged as a `state` event.

## Vulnerability scanning (opt-in)

MOLE is reconnaissance only by default. During `mole init` the wizard asks
a typed-confirmation question; enabling vulnerability scanning records
`vuln_scanning: true` in `scope.yaml` (an older release's `exploit: true`
is still honoured). When enabled:

- `nuclei` (template-based vulnerability detection) is registered as a tool;
  a reconnaissance engagement cannot reach it even if the model asks.
  The default run is a fast first pass (`exposures,cve,misconfig` tags);
  the model can pass specific tags for a targeted run. Fuzzing and
  antipattern templates are never run, and tech fingerprint templates are
  excluded from the default run.
- `ffuf` (rate-limited web directory fuzzing) is registered as a tool for
  web targets; a reconnaissance engagement cannot reach it even if the model
  asks. Rate limited to 10 req/s in code, wordlist capped at 5000 entries
  and results at 50 hits. It uses a built-in curated wordlist (admin
  panels, API/docs, config and source leakage like `.git`/`.env`/
  `web.config`, backups, CMS paths) and probes the extensionless paths plus
  common web-app extensions; the model can pass extensions or a local
  wordlist file for a targeted run.
- `web_check` (core web-bug validation) is registered as a tool for web
  targets. The model names the page URL, the input parameter, and the class
  (`sqli`, `lfi`, `rfi`, `cmdi`, `xss`, `upload`, `idor`); the tool fires a
  fixed set of non-destructive probes (it picks the payloads, so no
  destructive payload can reach the target through it) and returns a verdict
  (`detected` / `not_detected` / `inconclusive`) with per-probe evidence.
  An optional `headers` object is sent on every probe (e.g. a session
  `Cookie` obtained via `http_request`). Playbook details (what to look for,
  minimal payloads, safe validation) live in the embedded web-bug playbook,
  served via `knowledge_search`.
- `http_request` (model-directed HTTP) is registered as a tool for the
  crafted probes `http_probe` (GET-only) cannot express: POST forms, custom
  headers, arbitrary method from an allowlist (GET/POST/PUT/PATCH/DELETE/
  HEAD/OPTIONS). It follows redirects by default; `follow_redirects=false`
  stops at the first hop and returns that hop's status and `Location` (used
  to see where a redirect points without the request leaving the scope).
  Response body is capped at 8 KB.
- `exec` (on-target command execution) is registered as a tool for
  exploit-in-scope engagements. It is stateful: the first call registers the
  command-execution vector (url, method GET/POST, the injectable param, the
  shell separator, optional value prefix, extra form fields and headers) and
  verifies it with
  `id`; every later call passes only `command`. The command runs **on the
  target** through the vector — never in the harness — its output is cut out
  between echoed markers (8 KB body fallback), the vector host is
  scope-gated on every call, and the request shares the web tools' 10 req/s
  per-host rate limit. The first call records the foothold in the findings
  ledger, and the privilege-escalation checklist (see Technique knowledge)
  is what the model works through with it.
- The system prompt swaps the recon-only rule for vulnerability-scanning rules:
  the rate limits (nuclei 20 req/s, ffuf 10 req/s, web_check/http_request/exec
  10 req/s per host) are enforced in code, and the model must validate with
  the minimum needed and stop once a finding is confirmed — no DoS, no
  exfiltration, no changes; post-foothold escalation through `exec` is the
  one controlled exception.
- The report gains a "Vulnerability scanning" section, and the transcript's
  start event records `"vulnerability_scanning": true`.

`nuclei` and `ffuf` are bundled in the image (built with `go install` in the
Dockerfile's build stage and copied to `/usr/local/bin`). They are inert for
recon-only engagements — the registry gate keeps them unreachable without
`vuln_scanning: true` — but present so the container is self-contained.
`web_check`, `http_request` and `exec` are pure Go (stdlib only): no
binaries, no Dockerfile change. `shell` is the one tool that is *not* gated
by this opt-in — it is registered in every mode because it runs local
scripts in the harness, not on the target (see Guardrails for how that risk
is handled). Nuclei fetches its templates on first use; if a binary
is ever missing (e.g. running the harness on the host rather than in the
image) it degrades gracefully, exactly like `nmap`.

The plan for the remaining toolkits (Hydra/Metasploit deferred) lives in
[`docs/exploitation-toolkits.md`](docs/exploitation-toolkits.md).

## Technique knowledge (mini-RAG)

Every engagement gets the `knowledge_search` tool: a small retrieval layer
over the embedded technique docs, so the model can consult them at the
moment it needs it (a service is discovered, a foothold is gained, a
service/permission/cron/credential finding lands) instead of carrying the
full text in the system prompt.

- **Corpus.** `docs/service-enumeration.md` (per-service enumeration
  checklists: web/HTTP, SSH, RDP, databases, Samba, SMTP) and
  `docs/light-scripting.md` (adapting a public exploit into a small
  bash/python3 script: when to adapt, bash and python patterns, safety,
  keeping the script auditable in the transcript) are always loaded;
  `docs/linux-windows-basics.md` (the Linux & Windows basics: first minutes
  after a foothold, CLI, permissions, services, cron, credentials, lateral
  movement) and `docs/privilege-escalation.md` (the post-foothold
  privilege-escalation checklist: Linux sudo/SUID/cron, Windows tokens and
  stored credentials) and `docs/web-bugs.md` (the core web-bug playbook: what
  to look for, minimal payloads, safe validation) are loaded only when
  exploitation is in scope. All are
  embedded in the binary (the image ships only the binary and the model has
  no file access) and chunked at `##`/`###` headings; each chunk carries its
  source doc and heading path.
- **Retrieval.** Query and chunks are tokenised; chunks rank by weighted
  keyword overlap — a heading/doc-title hit weighs three times a body hit,
  and consecutive query terms both present earn a phrase bonus. Deterministic,
  dependency-free, and debuggable at this corpus size (tens of chunks). The
  scorer sits behind `Store.Search` in agent-core's `knowledge` package
  (shared with Collie), so an embedding-based scorer can replace it later
  without touching the tool or the prompt.
- **Gating.** `knowledge_search` is always registered (it reads the embedded
  corpus and never touches a target); the *corpus* is what changes — the
  post-foothold playbook and the privilege-escalation checklist are loaded
  only when exploitation is in scope (`vuln_scanning: true`). The system
  prompt points at it in both modes. A query with no overlap returns a hint,
  not an error.
- **Citation.** Hits are labelled `[n] source — heading`, so the model can
  cite the section it acted on in findings and the report.

## Components

| Path | Role |
|---|---|
| `internal/scope` | The scope gate: authorisation model + the hard in/out-of-scope check. |
| `internal/wizard` | Interactive startup scoping that produces a binding `scope.yaml`. |
| `internal/llm` | Minimal OpenAI-compatible chat client with function calling. |
| `internal/tools` | The gated recon tools (DNS, nmap, TCP, HTTP probe, TLS probe, security headers, subdomains), the findings tools (record/update finding), the opt-in vulnerability-scanning tools (nuclei, ffuf, web_check, http_request, exec + the shared per-host rate limiter), the always-available knowledge_search and shell tools + registry. |
| `internal/ledger` | The findings ledger: persistent working memory, re-injected every turn, rendered into the report. |
| `internal/agent` | The LLM-driven loop: prompt, tool dispatch, budget, report. |
| `main.go` | The CLI: `init`, `run`, `check`. |
| `Dockerfile` | Multi-stage image: static harness + nmap + bash/python3 (shell tool runtime) + nuclei + ffuf. |

## Scope of use

Only run MOLE against systems you are explicitly authorised to test. The
scope gate is a safeguard, not a substitute for that authorisation — and an
LLM is only as careful as the gate in front of it.
