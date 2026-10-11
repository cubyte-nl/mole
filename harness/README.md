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
   - the model calls tools (`dns_lookup`, `nmap`, `http_probe`, `tls_probe`, `tcp_probe`, `security_headers`, `subdomains`);
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
that port scanning is unavailable instead of failing. `nuclei` is likewise
optional (vulnerability scanning only) and degrades the same way when absent.

## Container

The container is the intended way to run recon: it bundles the harness with
`nmap`, keeps the tooling off the host, and makes runs reproducible. The LLM
stays outside the container.

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
- A tool-step budget (`--max-steps`, default 100) bounds autonomous runs; when
  it is exhausted the model is asked to write its final report from the
  evidence gathered so far.
- `Ctrl-C` aborts the run cleanly (context cancellation propagates to every
  in-flight tool).
- Every run is auditable: the JSONL transcript in the engagement directory
  records the model's reasoning, tool calls, and gate denials.

## Vulnerability scanning (opt-in)

MOLE is reconnaissance only by default. During `mole init` the wizard asks
a typed-confirmation question; enabling vulnerability scanning records
`vuln_scanning: true` in `scope.yaml` (an older release's `exploit: true`
is still honoured). When enabled:

- `nuclei` (template-based vulnerability detection) is registered as a tool;
  a reconnaissance engagement cannot reach it even if the model asks.
- The system prompt swaps the recon-only rule for vulnerability-scanning rules:
  the rate limit (20 req/s) is enforced in code, and the model must validate
  with the minimum needed and stop once a finding is confirmed — no fuzzing,
  no DoS, no exfiltration, no changes.
- The report gains a "Vulnerability scanning" section, and the transcript's
  start event records `"vulnerability_scanning": true`.

`nuclei` is bundled in the image (built with `go install` in the Dockerfile's
build stage and copied to `/usr/local/bin`). It is inert for recon-only
engagements — the registry gate keeps it unreachable without `vuln_scanning: true` —
but present so the container is self-contained. Nuclei fetches its templates
on first use; if the binary is ever missing (e.g. running the harness on the
host rather than in the image) it degrades gracefully, exactly like `nmap`.

The plan for the remaining toolkits (ffuf is next) lives in
[`docs/exploitation-toolkits.md`](docs/exploitation-toolkits.md).

## Components

| Path | Role |
|---|---|
| `internal/scope` | The scope gate: authorisation model + the hard in/out-of-scope check. |
| `internal/wizard` | Interactive startup scoping that produces a binding `scope.yaml`. |
| `internal/llm` | Minimal OpenAI-compatible chat client with function calling. |
| `internal/tools` | The gated recon tools (DNS, nmap, TCP, HTTP probe, TLS probe, security headers, subdomains), the opt-in vulnerability-scanning tool (nuclei) + registry. |
| `internal/agent` | The LLM-driven loop: prompt, tool dispatch, budget, report. |
| `main.go` | The CLI: `init`, `run`, `check`. |
| `Dockerfile` | Multi-stage image: static harness + nmap + nuclei runtime. |

## Scope of use

Only run MOLE against systems you are explicitly authorised to test. The
scope gate is a safeguard, not a substitute for that authorisation — and an
LLM is only as careful as the gate in front of it.
