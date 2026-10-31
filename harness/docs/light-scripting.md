# Light scripting: adapting exploits with small scripts

The `shell` tool runs bash and python3 locally in the harness. Public
exploits and techniques rarely fit a target as-is: the URL, port, path, or
payload is hardcoded, the tool needs a cookie the stock tools don't carry,
the output needs parsing, or the check must run over several in-scope hosts.
Adapt the technique with a small script instead of giving up — and keep the
script minimal enough to review in the transcript.

## When to adapt with a script

- A public exploit (nuclei template, exploit-db snippet, CVE write-up) targets
  a hardcoded URL, path, or payload that differs from your target: patch the
  values into a script.
- A technique needs state stock tools drop between calls — a session cookie
  across multiple requests, a token from one response used in the next, a
  multi-step login.
- The output needs parsing before it is usable — extracting a value from
  HTML/JSON, diffing two responses, collecting markers from many hosts.
- The same probe must run over a list of in-scope hosts or ports.
- Do not script what a stock tool already does: prefer `nuclei`, `web_check`,
  `http_request`, `nmap`, `dns_lookup` when they cover the check.

## Bash patterns

`curl`, `grep`, `sed`, `awk`, `python3`, `jq` (JSON) and `yq` (YAML) are installed.

- Patch and run an exploit one-liner:
  `curl -s http://TARGET:PORT/path -d 'id=1' | grep -o 'root:'` — replace the
  hardcoded host/port from the write-up with your in-scope target.
- Capture a value and reuse it:
  `tok=$(curl -s http://TARGET:PORT/login | grep -oP 'token="[^"]+"' | cut -d'"' -f2); curl -s http://TARGET:PORT/admin -H "X-Token: $tok"`.
- Session across steps: save cookies to a file and reuse —
  `curl -s -c /tmp/c.txt -d 'user=u&pass=p' http://TARGET:PORT/login && curl -s -b /tmp/c.txt http://TARGET:PORT/secret`.
- Loop over in-scope hosts (never more):
  `for h in host1 host2; do echo "== $h"; curl -s -o /dev/null -w '%{http_code}\n' http://$h:8080/; done`.
- Parse JSON/YAML responses with `jq`/`yq`:
  `curl -s http://TARGET:PORT/api | jq -r '.flag'`.
- Parse with python when the text is structured:
  `curl -s http://TARGET:PORT/api | python3 -c "import sys,json; print(json.load(sys.stdin)['flag'])"`.

## Python patterns

`python3` with the `requests` library is installed. Use it when the logic is
more than a one-liner.

- Sessions with cookies (login then authenticated request):
  `python3 -c "import requests; s=requests.Session(); s.post('http://TARGET:PORT/login',data={'user':'u','pass':'p'}); print(s.get('http://TARGET:PORT/admin').text)"`.
- Multi-step with a token: fetch the page, regex out the token, send it in a
  header; compare response texts for a boolean diff.
- Raw sockets for checks HTTP clients can't express (banner grabbing,
  protocol quirks): `socket.create_connection((host, port), timeout=5)`.
- Diffing two responses (blind-boolean checks): fetch both, print a short
  signature (length, hash, marker presence) rather than the full bodies.
- Keep scripts under a few dozen lines; pass the whole script as the
  `command` argument — multi-line scripts work.

## Safety

- Scripts may reach the network only toward in-scope targets; never touch
  out-of-scope hosts, never scan ranges beyond the scope.
- Non-destructive and minimal: read-only probes, fixed test values, no
  stacked queries, no data modification, no mass requests.
- Bound every run: a timeout on every call (the tool defaults to 60 s) and on
  every request inside a script; cap loops to the in-scope host list.
- If a script starts looking like a weapon (bulk exploitation, data
  exfiltration, privilege escalation against the target), stop — that is the
  job of the `exec` tool through a confirmed vector, and only after a finding
  is recorded.

## Auditability

The script is the `command` argument of the `shell` tool call, so the full
script text is recorded in the transcript verbatim — nothing is hidden in a
file. When a script confirms a technique:

- Record the finding with `record_finding` and quote the exact script (or its
  decisive line) in the evidence, so the report shows how the technique was
  adapted.
- Keep scripts self-contained in one call; if you must write a temp file,
  do it and consume it in the same script (e.g. `/tmp/c.txt` cookie jar), and
  note that in the finding.
- Cite the knowledge section (e.g. `light-scripting.md > Python patterns`)
  next to the technique you adapted.
