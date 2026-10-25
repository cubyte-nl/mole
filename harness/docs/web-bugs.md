# Core web-bug playbook

Playbook for detecting and validating the core web bug classes — SQL
injection, XSS, local/remote file inclusion, file upload, command injection,
IDOR — on in-scope web applications. Served to the model through the
`knowledge_search` tool in vulnerability-scanning engagements (see
`harness/docs.go`, `internal/knowledge`). The doc is chunked by heading and
retrieved per query, so each section stands alone.

Division of labour: `nuclei` provides detection breadth (run it with the
tags `sqli,xss,lfi,rfi,cmdi,idor,fileupload` against the base URL);
`web_check` provides validation (fixed, non-destructive payloads; the tool
picks the payloads, you pick the URL and parameter); `http_request` is for
the crafted probes neither covers (POST forms, custom headers). Every
`web_check` and `http_request` request is rate-limited per host in code.
Validate with the minimum needed, record the verdict and evidence with
`record_finding`, and stop once a finding is confirmed.

- Session-gated pages: the tools do not keep cookies between calls. When a
  page requires a session, establish it with `http_request` (e.g. log in),
  take the `Set-Cookie` value from the response, and pass it as the `Cookie`
  header to every subsequent `web_check` and `http_request` call — without
  it the probes hit the login redirect and verdicts come back negative. For
  CSRF-protected logins, do one tight cycle: GET the login page (capture token
  and cookie from that response), then POST credentials with that same cookie
  and token.

## SQL injection

- Look for: numeric or string parameters that reach a database query — IDs
  (`?id=1`), search boxes, filters, sort/order fields, login forms.
- Signals: responses change between `AND 1=1` and `AND 1=2` (boolean blind);
  a single quote returns a database error page (error-based); `nuclei` with
  the `sqli` tag hits.
- Validation: `web_check` with `class=sqli` on the page URL and parameter.
  It fires five probes — the original value, `AND 1=1`, `AND 1=2`, a trailing
  quote, and `' OR '1'='1` — and decides: SQL error signature on the quote
  probe, or a boolean diff (baseline matches `AND 1=1` but not `AND 1=2`).
- Safety: no stacked queries, no `UPDATE`/`DELETE`/`DROP`, no data
  exfiltration, no `UNION SELECT` against production data. Confirmation needs
  only the diff or the error signature — that is the evidence, record it.
- If the parameter is POST-only (login, search form), craft the request with
  `http_request` (method POST, URL-encoded body) using the same minimal
  values, and record the observed diff as evidence.

## Cross-site scripting (XSS)

- Look for: parameters reflected into the HTML — search boxes, messages,
  profile fields, error messages that echo input.
- Signals: your exact input appears in the response body unmodified
  (reflection); the input sits inside an HTML context without `&lt;`
  escaping (unescaped reflection).
- Validation: `web_check` with `class=xss`. It sends a unique marker
  (`molexss-…`) and a raw HTML tag (`<svg/onload=alert(1)>`): the tag
  reflected unescaped is a reflected-XSS context; a reflected but escaped
  value is inconclusive — inspect the surrounding markup with `http_probe`
  for attribute or DOM sinks.
- Safety: the tag carries no script body beyond the inert `onload=alert(1)`
  proof point; never use payloads that execute code, steal cookies, or touch
  users' sessions.
- Limitation: DOM-based XSS (client-side sinks) is out of scope — there is no
  JS execution in this harness. Record reflected findings only.

## Local file inclusion (LFI)

- Look for: parameters that select a file — `page=`, `file=`, `template=`,
  `include=`, `doc=`; also path parameters and `X-Forwarded-For`-style
  headers on some stacks.
- Signals: the parameter's value appears in a path in the response;
  `nuclei` with the `lfi` tag hits; traversal variants return system files.
- Validation: `web_check` with `class=lfi`. It fires traversal variants of
  `../../../../etc/passwd`, a percent-encoded variant, and the absolute path;
  a `root:` line with `/bin/` in the response is confirmation.
- Safety: read-only, against system files only — never read, write or
  include application data, user data, or credentials. The `/etc/passwd`
  line is the evidence; do not enumerate further files.
- If all traversal variants are blocked (403/empty), that is a
  `not_detected` verdict with the blocked responses as evidence — note it and
  move on.

## Remote file inclusion (RFI)

- Look for: file-select parameters on PHP stacks with
  `allow_url_include` enabled; `page=`, `template=`, `background=`
  parameters.
- Signals: the parameter accepts `http://`/`file://` values; `nuclei` with
  the `rfi` tag hits.
- Validation: `web_check` with `class=rfi`. It references an unreachable
  host (`http://rfi-probe.invalid/x.php`) and `file:///etc/passwd`: an
  include-failure signature (e.g. "failed to open stream") or `/etc/passwd`
  content is confirmation.
- Safety: the unreachable host never receives a real payload and the `file://`
  probe reads a system file only — no external callback server, no data
  exfiltration.
- Limitation: RFI without an observable response difference is
  `inconclusive`, not negative — confirming it needs an out-of-band callback
  this harness does not run. Say so in the finding.

## File upload

- Look for: upload forms — profile pictures, avatars, document upload,
  `multipart/form-data` forms; file-field name in the form's HTML (read it
  with `http_probe`).
- Signals: the form accepts a file input; `nuclei` with the `fileupload` tag
  hits; upload endpoints without auth.
- Validation: `web_check` with `class=upload`, passing the endpoint URL and
  the file-field name (the form's `name=` on the file input). It POSTs one
  fixed harmless text file (`mole-upload-….txt`) and, if the response names
  the stored file, fetches it back: identical content is confirmation of an
  unrestricted upload.
- Safety: the file is a fixed, small, harmless text file with a `.txt`
  extension — never an executable, image-with-script, or polyglot. Upload
  only to endpoints you identified as user-file uploads, and only once.
- If the response does not name the stored file, the verdict is
  `inconclusive` — locate the stored file (directory listing, predictable
  path) and verify with `http_probe` before recording a finding.

## Command injection (cmdi)

- Look for: parameters passed to the shell — `ping`/`traceroute` forms,
  `host=`, `ip=`, `cmd=` parameters, printer/fax features, DNS tools in the
  web UI.
- Signals: `nuclei` with the `cmdi` tag hits; the parameter's value appears
  in a command in the response; shell metacharacters change the response.
- Validation: `web_check` with `class=cmdi`. It fires `;id`, `|id` and
  `$(id)` appended to the original value: `uid=… gid=…` output is
  confirmation.
- Safety: `id` is the only command — it reveals nothing sensitive and
  changes nothing. Never run commands that modify state, read data, or
  touch the network.
- If no command output is observed, the verdict is `not_detected`; if the
  probes error out (WAF, 500), it is `inconclusive` — note the responses.

## Insecure direct object references (IDOR)

- Look for: URL parameters that name objects — `?id=`, `?itemid=`,
  `?order=`, `?user=` — especially on authenticated pages and APIs.
- Signals: sequential object IDs; the parameter changes the returned object;
  `nuclei` with the `idor` tag hits.
- Validation: `web_check` with `class=idor`, passing the page URL and the
  object-ID parameter. It probes the original ID, the next ID, `1`, and
  `999999`: different object content for different IDs (all 200) means
  access control is not enforced where observable.
- Safety: read-only observation, no credentials, no enumeration beyond the
  four probes — no mass scanning of object IDs, no access to data that would
  require authentication you do not hold.
- Limitation: this is unauthenticated observation only ("where observable").
  Pages that redirect to login, return uniform 403/404, or serve identical
  content yield `not_detected`/`inconclusive` — say in the finding that
  authenticated behaviour was not tested.
