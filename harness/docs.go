package main

import _ "embed"

// linuxWindowsBasics is the post-foothold playbook for exploit-in-scope
// engagements (docs/linux-windows-basics.md). It is embedded — the container
// image ships only the binary (see Dockerfile) and the model has no file
// access — and served to the model through retrieval (internal/knowledge +
// the knowledge_search tool) rather than pasted into the system prompt.
//
//go:embed docs/linux-windows-basics.md
var linuxWindowsBasics string

// serviceEnumeration is the per-service enumeration checklists
// (docs/service-enumeration.md): what to check once a service is discovered
// (web, SSH, RDP, databases, Samba, SMTP). Always embedded and always loaded
// into the knowledge store — it applies to reconnaissance and
// vulnerability-scanning engagements alike.
//
//go:embed docs/service-enumeration.md
var serviceEnumeration string

// webBugs is the core web-bug playbook (docs/web-bugs.md): what to look for,
// minimal payloads, and safe validation for SQLi, XSS, LFI/RFI, file upload,
// command injection and IDOR — the division of labour between nuclei
// (detection breadth), web_check (fixed-payload validation) and http_request
// (crafted probes). Loaded into the knowledge store only when vulnerability
// scanning is enabled.
//
//go:embed docs/web-bugs.md
var webBugs string

// lightScripting is the light-scripting technique doc
// (docs/light-scripting.md): when and how to adapt a public exploit or
// technique into a small bash/python3 script with the shell tool, the safety
// rules for local scripts, and how the script stays auditable in the
// transcript. Always embedded and always loaded into the knowledge store —
// adapting techniques applies to reconnaissance and vulnerability-scanning
// engagements alike.
//
//go:embed docs/light-scripting.md
var lightScripting string

// privEscalation is the privilege-escalation checklist for exploit-in-scope
// engagements (docs/privilege-escalation.md): what to check and try once a
// foothold lands — Linux sudo/SUID/cron, Windows tokens and stored
// credentials — run through the exec tool. Embedded and loaded like the
// post-foothold playbook, served through knowledge_search.
//
//go:embed docs/privilege-escalation.md
var privEscalation string
