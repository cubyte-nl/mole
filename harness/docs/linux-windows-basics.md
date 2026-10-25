# Linux & Windows basics — post-foothold playbook

Source of truth for the post-foothold knowledge served to exploit-in-scope
engagements through the `knowledge_search` tool (see `harness/docs.go`,
`internal/knowledge` + `internal/tools`). The doc is chunked by heading and
retrieved per query, so keep each section dense and self-contained: a chunk
must stand on its own when returned, without the rest of the doc. The
post-foothold checklists here feed the deeper privilege-escalation checklist
(cubyte/mole#5), which lands the same way.

## Linux

### First minutes after a foothold (checklist)

1. Identify: `whoami`, `id` (group memberships often reveal the escape route),
   `uname -a`, `cat /etc/os-release`.
2. Orient: `pwd`, `ls -la`, `ps aux`, listening services `ss -lntp` (or
   `netstat -tlnp`), `ip a` / `ifconfig`.
3. Check direct privilege: `sudo -l` — every permitted command is a candidate
   escalation path; `NOPASSWD` entries are the strongest.
4. Harvest credentials you already sit on: `env`, `~/.bash_history`,
   `~/.ssh/`, files in the current directory (configs, scripts, key material).
5. Enumerate escalation vectors in this order (cheap → expensive):
   sudo → writable SUID binaries → writable cron entries → writable service
   units/scripts → writable dirs in `PATH` → `/etc/passwd` → kernel.
6. Record the foothold and each vector with `record_finding`, citing evidence.

### CLI basics

- `whoami` / `id` — who you are and which groups you are in.
- `ls -la` — dotfiles, hidden dirs, permission bits, ownership.
- `ps aux` — running processes and their users; root-only processes mark
  escalation targets (services, daemons).
- `ss -lntp` / `netstat -tlnp` — listening services and owning processes.
- `cat /etc/passwd` — accounts and login shells; world-readable.
- `cat /etc/shadow` — password hashes; readable only as root (its mere
  readability is a finding).
- `find / -perm -4000 2>/dev/null` — setuid-root binaries.
- `crontab -l`, `ls -la /etc/cron* /var/spool/cron` — scheduled jobs.
- `getfacl <file>` — extended ACLs that override the basic permission bits.
- `history` / `~/.bash_history` — what previous users typed (credentials,
  paths, tooling).

### Permissions

- `rwx` per class (owner / group / other); octal mode, e.g. `755` =
  `rwxr-xr-x`. A file is exploitable when *you* hold write, and the effect
  runs as *someone more privileged*.
- **setuid bit** (`4xxx`, e.g. `4755`): the process runs as the file's *owner*.
  Setuid-root binaries are the classic local escalation — look for writable
  ones, or wrappers (`nmap`, `vi`, `find -exec`, `awk`, `env`, `sudo`-style
  scripts) that can spawn a shell or run a file you control.
- **setgid bit** (`2xxx`): runs as the file's *group*; gains that group's
  rights.
- **sticky bit** (`1xxx`, dirs): only the owner may delete entries — usually
  not an escalation path by itself.
- **ACLs** (`getfacl`/`setfacl`): per-user/per-group entries that override the
  mode line. A file can be writable by a group you belong to even when the
  `rwx` line says otherwise — check ACLs before dismissing a file.

### Services

- **systemd**: units in `/etc/systemd/system/` and `/lib/systemd/system/`;
  `systemctl status <unit>`, `systemctl cat <unit>` show config. What matters:
  the `User=` the service runs as and `ExecStart` — a unit file you (or a
  group you are in) can write, or an `ExecStart` pointing at a script/binary
  you can replace, runs code as the service's user.
- **inetd / xinetd** (legacy): `/etc/inetd.conf` and `/etc/xinetd.d/` map
  services to the command that runs on connection — same write-to-execute
  logic as unit files.
- The *service account* is the target, not the ceiling: a service running as
  `www-data` is a foothold toward root if its unit/script/config is writable.

### Cron

- **Where entries live**: `/etc/crontab`, `/etc/cron.d/`,
  `/etc/cron.{hourly,daily,weekly,monthly}/`, per-user spools under
  `/var/spool/cron/` (Debian: `crontabs/`; RHEL: flat files) —
  `crontab -l` lists the current user's.
- **Format**: `min hour dom mon dow [user] command` (system crontabs include
  the user column; user spools do not).
- **Escalation pattern**: a job running as a more privileged user that
  references a script, binary, or `PATH`-relative command you can write to or
  shadow runs as that user. For each entry, check ownership and writability of
  the entry itself, everything it references, and the spool files of users you
  can write to.

## Windows

### First minutes after a foothold (checklist)

1. Identify: `whoami /all` (groups, logon), `whoami /priv` (privileges —
   `SeImpersonatePrivilege`, `SeBackupPrivilege` are the big ones),
   `systeminfo`, `hostname`.
2. Orient: `ipconfig /all`, `netstat -ano`, `tasklist`, `dir /a`.
3. Check direct privilege: `net localgroup Administrators` — are you in it?
   Local admin ≈ game over on a standalone box.
4. Harvest credentials you already sit on: `cmdkey /list`, browser credential
   stores, PuTTY sessions, Kerberos tickets (`klist`), current directory.
5. Enumerate escalation vectors: service binpaths you can write
   (incl. unquoted paths) → scheduled tasks you can modify → UAC bypass
   candidates → token impersonation (if `SeImpersonatePrivilege` is set).
6. Record the foothold and each vector with `record_finding`, citing evidence.

### CLI basics

- **cmd**: `whoami /all`, `net user`, `net localgroup`, `systeminfo`,
  `ipconfig /all`, `netstat -ano`, `tasklist`, `dir /a`, `schtasks /query`,
  `sc query` / `sc qc <svc>`, `cmdkey /list`, `quser`, `nltest /dclist:`
  (domain controllers).
- **PowerShell**: `Get-Service`, `Get-Process`, `Get-ScheduledTask`,
  `Get-ChildItem`, `Get-Content`, `Where-Object` (filtering in pipelines),
  `$_` (current pipeline item), `&` (call an executable),
  `Get-ExecutionPolicy` (matters for persistence).
- One-shot service enumeration:
  `Get-CimInstance Win32_Service | Select Name,PathName,StartName` —
  every service's binpath plus the account it runs as.

### Services

- `sc query` lists services; `sc qc <svc>` shows `binPath` and the service
  account (`obj=`). A service running as `LocalSystem`/admin with a binpath
  (or config it reads) you can write to = privilege escalation.
- **Unquoted service path**: binpath contains spaces and no quotes, e.g.
  `C:\Program Files\App\svc.exe`. Windows parses the path at the first space,
  so a writable prefix directory lets you drop a `svc.exe` (or DLL) that
  loads first — classic, reliable escalation.
- Check both the executable and any config/script it loads.

### Scheduled tasks

- `schtasks /query /v /fo LIST` — full detail, including the run-as account.
  PowerShell: `Get-ScheduledTask` + `Get-ScheduledTaskInfo`.
- Escalation: a task running as `SYSTEM`/admin that executes a script or
  binary you can write to, or a task definition you can modify
  (`schtasks /change` / task XML).

### Where credentials live

- **lsass.exe**: holds logged-on credential material (passwords, hashes,
  Kerberos tickets) in memory; dumping the process (`procdump -ma lsass.exe`)
  exposes it. The canonical "where do credentials live" answer on Windows.
- **Registry**: `HKLM\SECURITY` (SYSTEM hive) + `HKLM\SYSTEM` (SAM) carry
  local account hashes; `reg save` extracts them for offline cracking.
  Cached domain hashes also live in `HKLM\SECURITY` (Lsa).
- **Credential files**: `cmdkey /list` (stored target credentials); browser
  `Login Data` stores; PuTTY session registry keys
  (`HKCU\Software\SimonTatham\PuTTY\Sessions`) including saved keys;
  `unattend.xml`/sysprep answer files with setup passwords;
  `netsh wlan export profile` (Wi-Fi passwords in XML).
- **Kerberos**: tickets in memory (lsass); `klist` lists them; a ticket for
  user X moves you to X's hosts (pass-the-ticket).

### Lateral movement (after the foothold)

Pattern: valid credential (or hash/ticket) → pick a channel → shell on the
next host → repeat the checklist.

- **SMB admin shares**: `\\host\C$` with valid creds — stage a binary, then
  run it.
- **Service creation** (psexec-style): `sc \\host create svc binPath=
  C:\path\evil.exe` then `sc \\host start svc`.
- **WMI**: `Invoke-WmiMethod -Class Win32_Process -Name Create -Arguments
  @{Command="cmd.exe /c whoami"} -ComputerName host`.
- **WinRM**: `Enter-PSSession host` / `Invoke-Command` (needs 5985/5986 open
  and remoting enabled).
- **RDP** (3389) when you have valid creds and it is open.

## Interpreting findings (apply to every result)

- **Service finding** (open port + banner): identify product and version,
  note the service account context, then map it to known weaknesses — and
  remember the post-foothold checklist applies once a shell lands.
- **Permission finding** (mode bits, ACL, setuid): name the class, the
  owner/group, and who holds write — then state the concrete escalation path
  it implies (what runs as whom when you touch it).
- **Cron / scheduled-task finding**: identify the run-as account, the
  referenced script/binary, and whether any link in that chain is writable by
  a lower-privileged user.
- **Credential finding** (hash, file, ticket): state where it lives, what it
  unlocks, and the abuse path (crack / pass-the-hash / pass-the-ticket).
  Never print raw secrets in the report — reference them by location.
