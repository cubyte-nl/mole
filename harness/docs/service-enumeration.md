# Service enumeration checklists

Source of truth for the per-service enumeration checklists served to the
model through the `knowledge_search` tool (see `harness/docs.go`,
agent-core's `knowledge` package + `internal/tools`). The doc is chunked by heading and
retrieved per query, so each section must stand alone when returned, without
the rest of the doc. Query it with the service name ("ssh enumeration",
"mongodb", "web directory fuzzing") as soon as nmap reports the service.

## General rules

- Every open service gets a banner and version first (`nmap -sV` does this in
  the default scan; re-scan the specific port with `--script <family>` for
  details). Record the observed banner and version with `record_finding`.
- Map version → known CVEs: run `nuclei` against the URL (or the host with
  the matching templates); the `cve` tag is part of the default first pass.
  A version with a known CVE is a finding even before you validate the
  vector.
- Run at least one service-specific check per discovered service (the
  per-service sections below), before moving on to the next service.
- Only stop enumerating for a documented reason — step budget exhausted, no
  further evidence of exposure, or the service is out of scope. Say the
  reason in the report.
- Default/weak credentials: test them only when the engagement explicitly
  authorises credential testing, and record what you tested and the result.

## Web (HTTP/HTTPS)

- Start with the passive probes: `http_probe` (status, title, redirect
  target), `security_headers`, and `tls_probe` (certificate CN/SANs, expiry,
  chain) — SANs and the title often reveal the real application name and
  other in-scope hosts.
- Directory fuzzing: run `ffuf` against the base URL (and any sub-path the
  probe revealed, e.g. `/app`). The built-in wordlist covers admin panels,
  API/docs (swagger, openapi), config & source leakage (`.git`, `.env`,
  `web.config`, `package.json`), backups (`old/`, `backup`), and CMS paths
  (`wp-admin`, `wp-json`, `xmlrpc.php`, `drupal`). Pass `extensions` for a
  targeted run.
- Read the hits: a 200 on `/admin` is an exposed panel; a 403/401 on
  `/wp-admin` means the CMS is present even if access is denied; a 200 on
  `.git/config` is source leakage — inspect what it reveals and record it.
- Setup/install surfaces: probe the application's setup and install
  endpoints (`setup.php`, `install.php`, `/setup`, `/install`) directly —
  they are often reachable after initialisation, and a live create/reset
  control is a finding in itself (see the web-bug playbook's setup section).
- Check `robots.txt` and `sitemap.xml`: they list paths the operator wanted
  hidden from crawlers.
- API surfaces: if `/api`, `/v2`, `/v3` or a swagger doc responds, probe the
  documented endpoints for unauthenticated access and record them.
- Run `nuclei` against the base URL (default first pass) and, for exposed
  panels, a targeted run with matching tags.
- Record every exposed path with its evidence line (status, length, title).

## SSH

- Re-scan the port with `nmap --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 <host>`:
  ciphers/MACs/kex in use, host key types, and the auth methods offered.
- Weak algorithms are a finding: 3des-cbc, arcfour, ssh-dss (SHA-1 DSA keys),
  and MD5-based MACs. Note them with the observed algorithm list as evidence.
- Anonymous login (`none` in the auth methods) is a critical finding —
  record it immediately.
- Banner/version → CVEs via `nuclei`; old OpenSSH versions are the common
  case (e.g. pre-auth RCE in specific releases).
- Default/weak credentials: only if the engagement authorises credential
  testing — test against the authorised account set, record the outcome,
  and do not retry beyond the stated limit.

## RDP (remote desktop)

- Re-scan with `nmap --script rdp-ntlm-info,rdp-enum-vulns -p 3389 <host>`:
  the RDP version, the domain the host claims, and known RDP vulnerabilities
  (BlueKeep-class pre-auth RCE is the headline one — confirm the version
  against the CVE before claiming it).
- Version → CVEs via `nuclei`; an exposed RDP on a publicly reachable host
  is a finding in itself (brute-force target), independent of version.
- Note whether NLA appears enabled (the script output) and record the
  banner string as evidence.
- Default/weak credentials: only if authorised (see the general rules);
  RDP is the service where unauthorised credential testing causes the most
  lockout noise, so the authorisation must be explicit.

## Databases (MySQL, PostgreSQL, MSSQL, MongoDB, Redis)

- Banner/version first: `nmap -sV` on the port; databases print versions in
  their banners more reliably than almost any service.
- MongoDB (27017): an open port is already a finding; run `nuclei` with
  exposure tags (unauthenticated access, default `admin/admin`). Record the
  database names the response reveals, do not pull data.
- Redis (6379): open, unauthenticated Redis is a finding; `nuclei` covers
  the standard checks (info disclosure, no-auth access). Record the version
  from the banner.
- MySQL (3306) / PostgreSQL (5432): version → CVEs via `nuclei`; `nmap
  --script mysql-empty-password,mysql-enum` and `pgsql-brute` are auth
  attempts — run the empty-password check only; a hit is a critical finding.
- A database port open to the internet (vs internal-only) doubles the
  severity of everything else on that host: record the exposure.
- **Authenticated from a foothold** (exploitation in scope, valid database
  credentials harvested from the target): the DB host becomes a
  code-execution target. Record the grants as evidence:
  - MySQL: `SHOW GRANTS FOR CURRENT_USER();` — `FILE` privilege plus a
    writable `@@plugin_dir` ⇒ load a UDF ⇒ RCE; `SUPER` opens `INTO OUTFILE`.
  - PostgreSQL: superuser (`rolsuper` in `pg_roles`) ⇒
    `COPY (SELECT 1) FROM PROGRAM 'id'`, or `lo_import` of a shared object.
  - MSSQL (1433): `xp_cmdshell` enabled ⇒ direct OS command execution.
  The RCE capability is itself a finding; if the DB host is out of scope,
  apply the lateral-movement passive rule: record, do not exploit.

## Samba (445)

- Re-scan with `nmap --script smb-enum-shares,smb-os-discovery,smb-vuln-ms17-010 -p 445 <host>`:
  the OS/SMB version, the shares that exist, and the EternalBlue-class
  pre-auth RCE (MS17-010) status.
- A share with anonymous read access is a finding — record the share name
  and what the script reports as its contents.
- Version → CVEs via `nuclei`; old SMBv1-only implementations get the
  EternalBlue family of vulnerabilities.
- An SMB service on a host that also runs a web app often exposes the
  backend filesystem to lateral movement: note that relationship in the
  finding.

## SMTP (25)

- Re-scan with `nmap --script smtp-commands,smtp-open-relay -p 25 <host>`:
  the banner/version, the commands the server accepts, and whether the relay
  is open.
- An open relay is a finding in itself (spam/abuse channel) — record the
  script's verdict as evidence.
- `smtp-enum-users` is an active user enumeration: run it only if the
  engagement authorises it, and record the outcome.
- Banner/version → CVEs via `nuclei` (Exchange and the big mail servers are
  the usual targets).
