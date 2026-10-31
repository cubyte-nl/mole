# Core web-bug playbook

Playbook for detecting and validating web bug classes on in-scope web
applications — SQL injection (including blind, and impact assessment:
schema scope and file access), XSS (reflected, stored, DOM), local/remote
file inclusion, file upload, command injection, IDOR, CSRF, authorisation
bypass, open redirect, weak session identifiers, brute-force resistance,
credential reuse, insecure CAPTCHA / weak CSP, and exposed setup/install
endpoints. Served to the model through the `knowledge_search` tool in
vulnerability-scanning engagements (see `harness/docs.go`,
agent-core's `knowledge` package). The doc is chunked by heading and retrieved per
query, so each section stands alone.

Division of labour: `nuclei` provides detection breadth (run it with the
tags `sqli,xss,lfi,rfi,cmdi,idor,fileupload` against the base URL);
`web_check` validates the fixed-payload GET classes (the tool picks the
payloads, you pick the URL and parameter); `http_request` is for the
crafted probes neither covers (POST forms, custom headers, state-changing
endpoints). The classes that need a session carried across calls, a timing
measurement, or a read of the page's own JavaScript go through
`http_request` and small `shell` scripts (see the light-scripting guide).
Every `web_check` and `http_request` request is rate-limited per host in
code. Validate with the minimum needed, record the verdict and evidence
with `record_finding` — including the fix direction the section names —
and stop once a finding is confirmed.

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
- If the boolean diff is invisible (no row change, no error), see
  *Blind SQL injection* for the time-based fallback on the same input.
- Fix direction: parameterised queries / prepared statements everywhere;
  never build SQL from input.

## Blind SQL injection

- Look for: the same query-reaching parameters `web_check` with
  `class=sqli` already probed, where neither a row change nor an error is
  observable — time-based blind is the fallback for those inputs.
- Signals: `web_check` returned `not_detected`/`inconclusive` on a parameter
  that is clearly a query input; a sleep payload changes the response delay.
- Validation: a small `shell` script (python3 + requests) timing two
  requests — the original value, and the same value with a sleep appended
  (`... AND SLEEP(5)` for MySQL, `... AND pg_sleep(5)` for PostgreSQL,
  `...; WAITFOR DELAY '0:0:5'` for MSSQL) — a consistent multi-second gap
  only on the payloaded request is confirmation. Fire each variant at most
  once; keep the measured delays in seconds as the evidence.
- Safety: a sleep only — no data exfiltration, no stacked writes, no
  `UNION`. The delay is the evidence; never extract data character by
  character.
- Limitation: caching or a WAF can mask the delay — an unchanged response
  time is `not_detected` for this technique, not proof of safety.
- Fix direction: parameterised queries / prepared statements; the sleep
  payload only works on string-built SQL.

## SQLi impact: schema scope and file access

- Look for: a confirmed SQL injection with a read channel — an error page
  that echoes query data, `UNION` results visible in the page, or a stable
  boolean marker. Confirmation is the entry ticket; the finding's severity
  is set by what the application's database account can reach beyond the one
  parameter.
- Signals: `information_schema` is readable; the account can query schemas
  the application does not need; the web account is a database owner or
  carries the `FILE` privilege.
- Validation: two bounded probes through the read channel that confirmed
  the injection (the `http_request` or `shell` script that fired it).
  (1) Schema scope: `database()` and `current_user()`, then names only —
  the schema list and the current schema's table names (`GROUP_CONCAT` over
  `information_schema.tables`/`.columns`). Metadata, not production data:
  the names establish the blast radius and are the evidence. (2) File
  access: `LOAD_FILE()` on one small known system file — content returned
  means the account can read server files (application config with other
  credentials is the usual prize; chain to *Credential reuse*).
  `INTO OUTFILE`/`INTO DUMPFILE` into a web-writable path is a webshell
  precursor (RCE), but it writes to the target: run it only when the
  engagement explicitly authorises file writes — one minimal marker file,
  recorded — and the finding is then the write capability (the RCE path),
  not the file itself. Without that authorisation, record the write
  capability as inferred (a `LOAD_FILE` success implies the `FILE`
  privilege, and with it write) and mark it unverified.
- Safety: names only — no row-level data, no `UPDATE`/`DELETE`/`DROP`,
  `LOAD_FILE` read-only against system files, no writes without explicit
  authorisation. Stop once the capability is confirmed — the capability is
  the finding, not the data.
- Impact chain: SQLi + file read → config/credential exposure → *Credential
  reuse*; SQLi + file write into a web path → RCE → the post-foothold
  playbook.
- Fix direction: parameterised queries everywhere; a least-privilege
  database account (schema-scoped grants, no `FILE`).

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
- Stored (persistent) and DOM-based (client-side) XSS are separate sections
  in this playbook — check them after reflected, on the same inputs.
- Fix direction: context-aware output encoding on every reflection, input
  validation, and a CSP that blocks inline script.

## Stored XSS

- Look for: inputs that are saved and later rendered for readers — profile
  fields, comments, messages, names in a list, form text echoed back on a
  read page.
- Signals: a write form exists for the field; a value you set reappears in a
  page other than the one you submitted it on.
- Validation: establish a session (the session-gated-pages note above), POST
  an inert marker (`molestored-…` plus `<svg/onload=alert(1)>`) into the
  field with `http_request`, then GET the page that displays the stored value
  and check the marker is present unescaped. Cite both requests.
- Safety: inert payload only (no script body, no cookie access), your own
  account's data, one submission, on a field you identified; the value stays
  on the target — note in the finding that a harmless marker was left.
- Limitation: if the stored page is only visible to a *different* user, you
  can record the write-side evidence (accepted, rendered to you) — say so.
- Fix direction: context-aware output encoding on render, input validation,
  and a CSP that blocks inline script.

## DOM-based XSS

- Look for: client-side sinks fed by the URL or the DOM — `innerHTML`,
  `document.write`, `eval`, `setTimeout(string)`, `location`/`href` set from
  `location.search`/`location.hash`/`document.referrer`, `postMessage`
  handlers without an origin check.
- Signals: the page's own JavaScript reads attacker-controlled input and
  passes it to one of those sinks. Fetch the JS with `http_probe`/
  `http_request` and read it; use `shell` + `curl` for files past the
  8 KB probe cap.
- Validation: static analysis only — quote the exact JS line(s) that form
  the source-to-sink chain (no sanitiser in between) as evidence. This is
  **static analysis — not executed**: the harness has no JS runtime, so do
  not claim an executed payload.
- Safety: reading the page's own served JavaScript is passive; no payload is
  ever sent into the application.
- Limitation: minified or obfuscated JS may hide the sink — when you cannot
  read the chain, record it as a lead, not a confirmed finding.
- Fix direction: avoid unsanitised input in JS sinks — `textContent` instead
  of `innerHTML`, allow-list redirect targets, check `event.origin` in
  `postMessage` handlers.

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
- Impact chain: an LFI that can reach the upload directory is often a full
  compromise by itself — pair it with the *File upload* section (unrestricted
  upload + includable storage = remote code execution on stacks that execute
  included scripts). Record the chain in the finding, not just the LFI.
- Fix direction: resolve the parameter against an allow-list of known files,
  or strip it to a base name (`basename()`); never include a raw user value,
  and keep user uploads out of any includable path.

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
- Fix direction: disable `allow_url_include` and include only allow-listed,
  application-controlled paths.

## File upload

- Look for: upload forms — profile pictures, avatars, document upload,
  `multipart/form-data` forms; file-field name in the form's HTML (read it
  with `http_probe`).
- Signals: the form accepts a file input; `nuclei` with the `fileupload` tag
  hits; upload endpoints without auth.
- Validation: `web_check` with `class=upload`, passing the endpoint URL and
  file-field name (the form's `name=` on the file input). It POSTs one fixed
  harmless text file (`mole-upload-….txt`) and, if the response names the
  stored file, fetches it back: identical content confirms an unrestricted
  upload.
- Safety: a fixed, small, harmless `.txt` file — never an executable,
  image-with-script, or polyglot; upload only to endpoints you identified as
  user-file uploads, once.
- If the response does not name the stored file, the verdict is
  `inconclusive` — locate the stored file (directory listing, predictable
  path) and verify with `http_probe` before recording it.
- Impact chain: unrestricted upload + the file stored where the web server
  can serve/execute it = remote code execution (on a script-executing stack,
  upload a script and include it — the *LFI* pair above). A server-side
  filter that checks only the extension (not the content) is an amplifier:
  double-extension and polyglot files bypass it. Record the chain, not just
  the upload.
- Fix direction: allow-list extensions **and** inspect content (magic bytes,
  not the file name), store uploads outside the web root or under a random
  non-executable name, and serve them with a non-executable `Content-Type`.

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
- Fix direction: never pass input to a shell — call the underlying operation
  through parameterised APIs, or allow-list the value strictly.

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
- Fix direction: a server-side ownership/role check on every object access
  (default deny), with unguessable object IDs (UUIDs) as a second layer.

## Cross-site request forgery (CSRF)

- Look for: state-changing endpoints (log in, change password/email,
  transfer, delete, settings) whose forms and API calls carry no anti-CSRF
  token.
- Signals: no `token`/`_csrf`-style field or header in the form's HTML (read
  it with `http_probe`); the endpoint accepts the change with only the
  session cookie present.
- Validation: with your own session, two steps — (1) `http_request` the
  state-changing endpoint *without* the token field (session cookie only)
  and observe whether it succeeds; (2) where a token is present in the form,
  confirm that is what the server checks. Cite the form HTML (absent token)
  and the tokenless request's response as evidence.
- Safety: your own account/session only, against changes that are reversible
  or already yours — never another user's data; prefer confirming the
  *absence* of a token (static, from the form HTML) over performing the
  change where possible.
- Limitation: a token in the form is not proof it is validated server-side —
  say "token present, validation not confirmed" unless you observed a
  tokenless attempt being rejected.
- Fix direction: per-session anti-CSRF tokens on every state-changing
  request, `SameSite=Lax` (or stricter) cookies, and Origin/Referer
  verification.

## Authorisation bypass

- Look for: functionality gated by role or ownership — admin panels, other
  users' records, billing pages, "delete account" — reachable by URL alone.
- Signals: an IDOR-style object parameter on an admin endpoint; a page that
  403s with a low-privilege cookie but 200s with none; hidden routes in the
  served JS (`/admin/…`, `?role=admin`) that answer when requested directly.
- Validation: request the protected resource with `http_request` (or
  `http_probe`) three ways — no session, a low-privilege session (your own),
  and a higher-privilege session **only if the engagement gave you that
  account**. A 200 with the resource content for the no-session or
  low-privilege request is confirmation. Cite the status and a content
  marker for each way.
- Safety: read-only; your own account(s) only; no privilege-escalation
  attempts (observe whether the endpoint checks a role parameter, do not
  forge one into a working access), no other users' data.
- Limitation: a uniform 403/404 for everyone is `not_detected` for this
  technique — the control may exist; say in the finding what you did and did
  not test.
- Fix direction: a server-side access-control check on every request
  (default deny), object-ownership checks per request, and no reliance on
  client-side hiding of the route.

## Open redirect

- Look for: parameters that carry a destination — `url=`, `next=`,
  `redirect=`, `return=`, `dest=`, `continue=` — on login, logout, payment,
  and "go back" links.
- Signals: the parameter's value appears in a `Location` header or a
  `window.location` in the page; lax handling of relative vs absolute
  values.
- Validation: `http_request` with `follow_redirects=false` (so the request
  never leaves the target) on the page with the parameter set to an
  obviously-external, inert value (`http://example.invalid/`): a 3xx whose
  `Location` is your external value is confirmation. Then try at most one
  bypass shape each: `//example.invalid/`, `https:example.invalid/`. Cite
  the status + `Location` of each probe.
- Safety: `follow_redirects=false` is mandatory here — the external value is
  observed in the header, never fetched, so no request leaves the scope; use
  a non-existent domain so nothing real is ever the target.
- Limitation: JavaScript-driven redirects (`window.location` in the served
  page) are visible only by reading the page source — record them as
  static-analysis leads, not executed.
- Fix direction: an allow-list of own domains/paths for redirect targets;
  reject (or normalise) absolute and protocol-relative values that point
  off-site.

## Weak session identifiers

- Look for: the application's session cookie — its name, value format,
  length, and how it changes (on login, on privilege change).
- Signals: short IDs (under ~16 hex chars / 64 bits); sequential or
  timestamp-shaped values (two sessions issued close together differ only in
  the last digits); human-readable IDs (names, e-mails, counters).
- Validation: with your own login, capture the `Set-Cookie` value from the
  login response (`http_request`), then compare it against a second session
  (log out, log in again): the length, the alphabet, and the delta between
  the two values are the evidence. A predictable delta or a low length is a
  finding.
- Safety: observe your own session IDs only — never request, guess or replay
  another user's session; no session-fixation attempt (do not plant a cookie
  and log in with it).
- Limitation: two samples cannot prove the generator's entropy — record the
  observed format and say "weak as observed", and note the cookie's flags
  (`HttpOnly`, `Secure`) from the same response.
- Fix direction: 128-bit+ IDs from a CSPRNG, rotated on login and on
  privilege change, sent with `HttpOnly`, `Secure` and a scoped `Path`.

## Brute-force resistance

- Look for: login forms, password-reset flows, API authentication — anywhere
  a guessable secret is checked over HTTP.
- Signals: no CAPTCHA on the login form; no delay or lockout observed on
  repeated failures; a "user not found" vs "wrong password" split (user
  enumeration is a finding in itself).
- Validation: **only when the engagement explicitly authorises credential
  testing.** A bounded probe, not a cracking attempt: submit the same
  authorised test credential 3–5 times with `http_request` and record what
  the server does — flat success/fail with no delay, no lockout, no CAPTCHA
  escalation is a finding ("no brute-force protection"). Cite the repeated
  responses, and any lockout/CAPTCHA change, as evidence.
- Safety: a handful of attempts on an authorised account only; stop
  immediately on a lockout or CAPTCHA (that is the control working); no
  wordlists, no mass usernames, no other users' accounts.
- Limitation: no lockout in five tries is not proof there is none at fifty —
  record the attempt count in the finding.
- Fix direction: rate limiting and account lockout with back-off,
  CAPTCHA/MFA after repeated failures, and a generic failure message (no
  user enumeration).

## Credential reuse

- Look for: any credential harvested anywhere in the engagement — the
  application's database credentials from a config file (via SQLi, LFI or
  RCE), application account credentials from a user-table dump, service
  credentials from a post-foothold harvest — that a different in-scope
  service might accept.
- Signals: the database username is also a plausible application login name;
  the same password appears in two configs; a config-file credential gates
  both the backend and the application's login.
- Why it matters: a successful reuse is a finding in its own right —
  cross-service credential sharing, typically high severity — even when each
  service shows no bug of its own.
- Validation: bounded — try the harvested credential pair against the
  in-scope login (the application's login form via `http_request`; other
  services via `shell` + `nc`/`curl`). A handful of attempts per pair — a
  reuse test, not a cracking attempt. One success is confirmation: cite the
  login request and the authenticated response.
- Safety: in-scope services only; a handful of attempts per credential pair,
  no wordlists, no mass spraying; only when the engagement authorises
  credential testing (the same gate as *Brute-force resistance*); no account
  changes; stop on a lockout (that is a control working).
- Limitation: a failed attempt proves nothing about the other services —
  record what was tested and the outcome.
- Fix direction: unique credentials per service, no shared secrets, a
  secrets manager instead of config files, and rotation on exposure.

## Insecure CAPTCHA and weak CSP

- Look for: login/reset forms with a CAPTCHA, and the
  `Content-Security-Policy` header on any page (start with the login and
  main pages).
- Signals: a CAPTCHA image or question that is static across reloads; an
  answer that is also in the page source; a CAPTCHA field the server ignores
  when absent. A missing CSP, or one with `unsafe-inline`/`unsafe-eval` in
  `script-src` (or no `script-src`, leaving `default-src` to govern).
- Validation: two independent checks. (1) CAPTCHA: reload the login page
  twice and compare the challenge (identical = weak); then submit the form
  with the CAPTCHA field empty or a fixed value and observe whether the
  server still processes it — bounded exactly like the *Brute-force
  resistance* section, and only when the engagement authorises credential
  testing. (2) CSP: `security_headers` gives the per-header verdict; cite
  the observed header value.
- Safety: CAPTCHA bypass attempts are a handful of form submissions on an
  authorised login; no image-OCR pipeline, no mass solving.
- Limitation: a CAPTCHA you did not break is `not_detected` for the bypass
  (it may simply be strong); the CSP verdict is exact — the header is
  present, absent, or weak, as observed.
- Fix direction: server-side CAPTCHA enforcement (reject when missing or
  wrong) with unique per-session challenges; a strict CSP (`default-src
  'self'`, no `unsafe-inline`/`unsafe-eval`, `frame-ancestors` set) on all
  HTML responses.

## Setup and install endpoints

- Look for: install and setup surfaces — `setup.php`, `install.php`,
  `install/`, `/setup`, `/install`, `wp-activate.php`, `installer/`, and the
  application's own setup wizard — on any in-scope web application, fresh
  installs in particular. Directory fuzzing often finds them; probe
  candidate paths directly.
- Signals: a setup page answers (200 with a form) on an already-initialised
  application; live "Create database" / "Reset database" / "Reinstall" /
  "Drop tables" controls; a setup form that accepts a database-connection
  string.
- Validation: read-only — `http_probe`/`http_request` GET the endpoint and
  read the form: a live create/reset/reinstall control is the finding. Cite
  the form HTML (the control's name and label) as evidence.
- Safety: never submit reset/reinstall/create against a live system — it
  destroys data, and that destruction is exactly the impact being reported;
  the live control's presence is the evidence. A controlled demonstration is
  possible only on a disposable instance, and only with operator
  confirmation.
- Impact: availability (an attacker wipes the application's data),
  integrity (re-initialisation resets users and roles; a fresh init often
  creates a default admin), and — where the setup form takes a
  database-connection string — a channel to exfiltrate the application's
  backend configuration or point the application at an attacker-controlled
  database.
- Fix direction: remove setup/install endpoints from production, gate them
  (one-time token, IP allow-list), and auto-delete them after
  initialisation.
