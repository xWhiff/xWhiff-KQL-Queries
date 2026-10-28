# CVE-2026-111497 ("Node2Shell") on macOS: Defender for Endpoint KQL

Written 2026-10-28. Revised the same day: **no TVM tables**. Everything below uses `DeviceProcessEvents`, `DeviceFileEvents` and `DeviceInfo` only. Re-check the advisories before acting; this one is moving fast.

## What it is (fact, sourced)

- Out-of-bounds write in Google's Brotli decoder (CWE-787 / CWE-252). A crafted Brotli stream pushes the decoder into an invalid block-switch state, which it treats as "need more input", so it keeps writing past an 8-byte buffer.
- Impact: crash (SIGSEGV), process memory disclosure, or RCE in the context of the decompressing process.
- Trigger: the app has to decompress attacker-controlled Brotli data. Two paths: a server that decompresses `Content-Encoding: br` request bodies, or a service that fetches an attacker-controlled URL and decompresses a `br` response.
- Severity: CVSSv4 9.2 (Google CNA). Not on CISA KEV as of 26 Oct. Public PoCs on GitHub. ELLIO reports in-the-wild exploit traffic from 94.154.43.7; Rapid7 had not seen exploitation as of 26 Oct. Treat as "exploitation starting".

| Component | Fixed in |
|---|---|
| Node.js 22 / 24 / 26 | 22.23.4 / 24.22.1 / 26.12.1 (20.x, 23.x, 25.x and older: no fix, treat as affected) |
| Google Brotli (libbrotli) | 1.0.10 / 1.1.1 / 1.2.1 |
| Bun | 1.4.4 |
| Python `Brotli` / `brotlicffi` | 1.2.1 / 1.2.1.0 |
| .NET 8 / 9 / 10 | 8.0.33 / 9.0.22 / 10.0.14 |

Also named: Envoy, Istio, brotli4j, FFmpeg, Apache Arrow, ClickHouse, cdxgen.

## Why the Mac angle is mostly exposure, not compromise

Public RCE was shown on Linux arm64 (Node 24.22.0). I found no published macOS exploit chain. On Macs the realistic risk is developer machines running local Node/Bun/.NET servers, internal tools that fetch URLs, and Homebrew `brotli`. So: find exposure from telemetry (queries 1 and 2), close the gaps on the host (step 2b), then hunt behaviour (queries 3 and 4).

## How version discovery works without TVM

MDE on macOS doesn't populate `ProcessVersionInfo*` (that's PE metadata, Windows only). But most Mac Node installs put the version **in the path**, so you can read it out of `FolderPath`:

| Install method | Typical path | Version in path? |
|---|---|---|
| nvm | `~/.nvm/versions/node/v22.23.3/bin/node` | Yes |
| Homebrew | `/opt/homebrew/Cellar/node@22/22.23.3_1/bin/node` | Yes (strip `_1` revision) |
| Volta | `~/.volta/tools/image/node/22.23.3/bin/node` | Yes |
| asdf | `~/.asdf/installs/nodejs/22.23.3/bin/node` | Yes |
| fnm | `~/Library/Application Support/fnm/node-versions/v22.23.3/installation/bin/node` | Yes |
| Official .pkg | `/usr/local/bin/node` | **No** |
| Bun | `~/.bun/bin/bun` | **No** |

For the "No" rows, query 1 borrows the version from any other device running the **same SHA256** where the path did reveal it. What's left goes to the host check in 2b.

Limit: advanced hunting keeps 30 days. A runtime that hasn't executed in 30 days won't show. That's acceptable for exposure (if it isn't running, it isn't decompressing anything), but say so in any report.

---

## Query 1: Node and Bun versions from process telemetry

```kql
let MacDevices = DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId;
let Fixed = datatable(Runtime:string, Major:int, FixedVersion:string)
[
    "node", 22, "22.23.4",
    "node", 24, "24.22.1",
    "node", 26, "26.12.1",
    "bun",  1,  "1.4.4"
];
let Runs =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where DeviceId in (MacDevices)
    | where FileName in~ ("node", "bun")
    | extend Runtime = tolower(FileName)
    | extend PathVersion = extract(@"/v?(\d+\.\d+\.\d+)(?:_\d+)?/", 1, FolderPath)
    | summarize LastRun = max(Timestamp), Runs = count(), Users = make_set(AccountName, 5)
        by DeviceName, Runtime, FolderPath, SHA256, PathVersion;
// Borrow a version for path-less installs from any device running the same binary hash
let HashVersion =
    Runs
    | where isnotempty(PathVersion)
    | summarize HashVer = take_any(PathVersion) by SHA256;
Runs
| join kind=leftouter HashVersion on SHA256
| extend Version = iff(isnotempty(PathVersion), PathVersion, HashVer)
| extend Major = toint(split(Version, ".")[0])
| join kind=leftouter Fixed on Runtime, Major
| extend Source = case(
    FolderPath has "/.nvm/", "nvm",
    FolderPath has "/Cellar/", "Homebrew",
    FolderPath has "/fnm/", "fnm",
    FolderPath has "/.volta/", "Volta",
    FolderPath has "/.asdf/", "asdf",
    FolderPath has "/.bun/", "Bun installer",
    FolderPath has ".app/", "Bundled in an app",
    FolderPath startswith "/usr/local/bin", "Official pkg",
    "Other")
| extend Status = case(
    isempty(Version), "UNKNOWN - check on host (2b)",
    Runtime == "node" and Major > 26, "Check advisory (newer line)",
    isempty(FixedVersion), "AFFECTED - EOL line, no fix, upgrade major",
    parse_version(Version) < parse_version(FixedVersion), "AFFECTED - patch available",
    "Patched")
| where Status != "Patched"
| project DeviceName, Runtime, Version, FixedVersion, Status, Source, FolderPath, SHA256, Users, LastRun, Runs
| order by Status asc, DeviceName asc
```

Logic: every `node`/`bun` that ran on a Mac in 30 days, with its version taken from the path or, failing that, borrowed from a matching hash. Then it compares against the fixed build for that major line. Node majors with no fix row (18, 20, 23, 25) come out as EOL-affected.

Prioritise rows where the same device also shows the runtime **listening** or making inbound connections:

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node", "bun", "dotnet")
| where ActionType in ("ListeningConnectionCreated", "InboundConnectionAccepted")
| join kind=inner (DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId) on DeviceId
| summarize Ports = make_set(LocalPort, 20), RemoteIPs = dcount(RemoteIP) by DeviceName, InitiatingProcessFolderPath
```

If your tenant doesn't log those ActionTypes for macOS, the query just returns nothing; it won't error.

## Query 1c: Vulnerable Node that is listening or fetching from the internet (priority list)

```kql
let MacDevices = DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId;
let Fixed = datatable(Major:int, FixedVersion:string)
[ 22, "22.23.4", 24, "24.22.1", 26, "26.12.1" ];
// 1. Every node binary that ran on a Mac, with its version
let NodeBins =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where DeviceId in (MacDevices)
    | where FileName =~ "node"
    | extend PathVersion = extract(@"/v?(\d+\.\d+\.\d+)(?:_\d+)?/", 1, FolderPath)
    | summarize by DeviceId, DeviceName, SHA256, FolderPath, PathVersion;
let HashVersion =
    NodeBins | where isnotempty(PathVersion)
    | summarize HashVer = take_any(PathVersion) by SHA256;
// 2. Keep the vulnerable (or unknown) ones
let Vulnerable =
    NodeBins
    | join kind=leftouter HashVersion on SHA256
    | extend Version = iff(isnotempty(PathVersion), PathVersion, HashVer)
    | extend Major = toint(split(Version, ".")[0])
    | join kind=leftouter Fixed on Major
    | extend Status = case(
        isempty(Version), "Unknown version - check on host",
        Major > 26, "Check advisory (newer line)",
        isempty(FixedVersion), "Affected - EOL line, upgrade major",
        parse_version(Version) < parse_version(FixedVersion), "Affected - patch available",
        "Patched")
    | where Status != "Patched"
    | project DeviceId, DeviceName, SHA256, FolderPath, Version, FixedVersion, Status;
// 3. What those binaries did on the network
let Net =
    DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where DeviceId in (MacDevices)
    | where InitiatingProcessFileName =~ "node"
    | where not(InitiatingProcessCommandLine has_any ("npm", "npx", "yarn", "pnpm", "corepack"))
    | extend Activity = case(
        ActionType in ("ListeningConnectionCreated", "InboundConnectionAccepted"), "Listening / inbound",
        ActionType == "ConnectionSuccess" and RemoteIPType == "Public", "Outbound to internet",
        "")
    | where isnotempty(Activity)
    | where not(RemoteUrl has_any ("registry.npmjs.org", "registry.yarnpkg.com", "nodejs.org", "github.com", "githubusercontent.com"))
    | summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
                LocalIPs   = make_set_if(LocalIP, Activity == "Listening / inbound", 10),
                LocalPorts = make_set_if(LocalPort, Activity == "Listening / inbound", 20),
                RemoteUrls = make_set_if(RemoteUrl, isnotempty(RemoteUrl), 20),
                RemoteIPs  = make_set_if(RemoteIP, Activity == "Outbound to internet", 20),
                CmdLines   = make_set(InitiatingProcessCommandLine, 5)
        by DeviceId, SHA256 = InitiatingProcessSHA256, Activity;
// 4. Vulnerable AND network-active
Vulnerable
| join kind=inner Net on DeviceId, SHA256
| extend LoopbackOnly = Activity == "Listening / inbound"
        and array_length(set_difference(LocalIPs, dynamic(["127.0.0.1", "::1"]))) == 0
| project DeviceName, Version, FixedVersion, Status, Activity, LoopbackOnly,
          LocalPorts, LocalIPs, RemoteUrls, RemoteIPs, FirstSeen, LastSeen, FolderPath, CmdLines
| order by Activity asc, LoopbackOnly asc, DeviceName asc
```

Logic: version from path (or borrowed by hash), joined on `DeviceId` + `SHA256` to network events from that exact binary. Listening on anything other than loopback, or fetching from public IPs, puts the device at the top. `LoopbackOnly = true` means only local processes can reach it: lower priority, not zero.

## Query 2: .NET, Python Brotli and Homebrew libbrotli from the file trail

These don't show a version in the process path, but their installs write versioned folders.

```kql
let MacDevices = DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId;
DeviceFileEvents
| where Timestamp > ago(30d)
| where DeviceId in (MacDevices)
| where FolderPath has_any ("Microsoft.NETCore.App", "dist-info", "/Cellar/brotli/")
| extend
    DotnetVer = extract(@"Microsoft\.NETCore\.App/(\d+\.\d+\.\d+)", 1, FolderPath),
    PyPkg     = extract(@"(?i)/(brotli|brotlicffi)-\d", 1, FolderPath),
    PyVer     = extract(@"(?i)/(?:brotli|brotlicffi)-(\d+\.\d+\.\d+(?:\.\d+)?)\.dist-info", 1, FolderPath),
    BrewVer   = extract(@"/Cellar/brotli/(\d+\.\d+\.\d+)", 1, FolderPath)
| extend Component = case(
        isnotempty(DotnetVer), ".NET runtime",
        isnotempty(PyVer), strcat("Python ", tolower(PyPkg)),
        isnotempty(BrewVer), "Homebrew libbrotli",
        "")
| where isnotempty(Component)
| extend Version = case(isnotempty(DotnetVer), DotnetVer, isnotempty(PyVer), PyVer, BrewVer)
| summarize LastSeen = max(Timestamp) by DeviceName, Component, Version
| extend Major = toint(split(Version, ".")[0]), Minor = toint(split(Version, ".")[1])
| extend FixedVersion = case(
        Component == ".NET runtime" and Major == 8,  "8.0.33",
        Component == ".NET runtime" and Major == 9,  "9.0.22",
        Component == ".NET runtime" and Major == 10, "10.0.14",
        Component == "Python brotli", "1.2.1",
        Component == "Python brotlicffi", "1.2.1.0",
        Component == "Homebrew libbrotli" and Minor == 0, "1.0.10",
        Component == "Homebrew libbrotli" and Minor == 1, "1.1.1",
        Component == "Homebrew libbrotli" and Minor == 2, "1.2.1",
        "")
| extend Status = case(
        isempty(FixedVersion), "Check advisory",
        parse_version(Version) < parse_version(FixedVersion), "AFFECTED - patch available",
        "Patched")
| where Status != "Patched"
| order by Status asc, DeviceName asc
```

Logic: reads versions out of `.../shared/Microsoft.NETCore.App/8.0.32/`, `.../site-packages/brotli-1.1.0.dist-info/` and `/opt/homebrew/Cellar/brotli/1.1.0/`. The big limit is that **this only sees installs or updates that happened in the last 30 days**, because a file event only fires when the file is written. Absence here doesn't mean absence on disk. Use 2b for coverage.

## Step 2b: Host check for the gaps (Live Response or MDM script)

For devices marked UNKNOWN, or for full coverage of .NET and Brotli, run this read-only script through MDE Live Response (`run` from the library) or as an Intune/Jamf script. It only prints versions.

```bash
#!/bin/bash
# CVE-2026-111497 exposure check. Read-only: prints runtime versions.
for u in /Users/*; do
  for p in "$u"/.nvm/versions/node/*/bin/node \
           "$u"/.volta/tools/image/node/*/bin/node \
           "$u"/.asdf/installs/nodejs/*/bin/node \
           "$u"/.bun/bin/bun; do
    [ -x "$p" ] && echo "$p $("$p" --version 2>/dev/null)"
  done
  # Python Brotli packages in user site-packages and venvs (shallow search)
  find "$u" -maxdepth 7 -type d \( -iname "brotli-*.dist-info" -o -iname "brotlicffi-*.dist-info" \) 2>/dev/null
done
for p in /usr/local/bin/node /opt/homebrew/bin/node /usr/local/bin/bun /opt/homebrew/bin/bun; do
  [ -x "$p" ] && echo "$p $("$p" --version 2>/dev/null)"
done
[ -x /usr/local/share/dotnet/dotnet ] && /usr/local/share/dotnet/dotnet --list-runtimes
ls -d /opt/homebrew/Cellar/brotli/* /usr/local/Cellar/brotli/* 2>/dev/null
```

Caveat: Live Response runs as root, and `--version` executes user-owned binaries as root. Low risk, but if you'd rather avoid it, parse versions from paths only, or for the official pkg read `/usr/local/include/node/node_version.h`.

---

## Query 3: Post-exploitation, runtime spawning a shell or LOLBin

```kql
let Runtimes = dynamic(["node", "bun", "dotnet", "python3", "python", "Python"]);
let Suspicious = dynamic(["sh", "bash", "zsh", "dash", "osascript", "curl", "nc", "ncat", "python3", "perl", "base64", "security", "launchctl"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| join kind=inner (DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId) on DeviceId
| where InitiatingProcessFileName in~ (Runtimes)
| where FileName in~ (Suspicious)
// Drop routine dev tooling: package managers, build tools, editors
| where not(InitiatingProcessCommandLine has_any ("npm", "npx", "yarn", "pnpm", "node_modules/.bin", "webpack", "vite", "jest", "eslint", "tsc", "next dev", "Visual Studio Code", "Cursor"))
// Keep only command lines that look like interactive shells, downloads or persistence
| where ProcessCommandLine has_any ("sh -i", "bash -i", "zsh -i", "/dev/tcp", "| sh", "|sh", "| bash", "base64 -d", "base64 --decode", "curl -s", "curl -fsSL", "mkfifo", "LaunchAgents", "LaunchDaemons", "find-generic-password", "dump-keychain", "do shell script")
    or (FileName in~ ("nc", "ncat"))
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

Logic: RCE through this bug runs as the decompressing process, so the first visible step is usually that runtime spawning a shell or a native tool (ATT&CK T1059.004 Unix Shell, T1059.002 AppleScript, T1105 Ingress Tool Transfer, T1555.001 Keychain, T1543.001 Launch Agent). It's generic, so it also catches other Node RCEs. That's a feature here.

## Query 4: Crash signal (SIGSEGV in a runtime)

Exploitation attempts are unreliable and crash the process first. macOS writes a crash report to `DiagnosticReports`.

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| join kind=inner (DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId) on DeviceId
| where ActionType == "FileCreated"
| where FolderPath has "DiagnosticReports"
| where FileName matches regex @"(?i)^(node|bun|dotnet|python3?)[-_ ].*\.(ips|crash)$"
| summarize Crashes = count(), First = min(Timestamp), Last = max(Timestamp),
            Reports = make_set(FileName, 5)
            by DeviceName, InitiatingProcessAccountName
| where Crashes >= 2
| order by Crashes desc
```

Logic: two or more runtime crashes on one Mac in a week. Pair any hit with Query 3 and with `DeviceNetworkEvents` for that device around `First`/`Last`.

---

## Likely false positives and tuning

| Query | Likely FPs | Tuning |
|---|---|---|
| 1 | Old Node versions that devs keep in nvm but rarely use. Runtimes inside apps (VS Code, Cursor, Slack helpers) showing as "Bundled in an app". | Don't suppress; it's exposure. Rank by `Runs`, `LastRun` and the listener query. Handle app-bundled rows by patching the app, not Node. |
| 1 | Hash-borrowed version wrong if two builds share a hash (unlikely). | Spot-check a few with 2b. |
| 2 | Leftover folders from uninstalled versions, `dist-info` in caches. | Confirm with 2b before raising a ticket. |
| 3 | Dev scripts (`postinstall` hooks, `child_process.exec` in build tools, Electron helper scripts), MDM scripts run via Python. | Extend the `ParentCmd` exclusion with known build tools; exclude signed MDM agents by `InitiatingProcessFolderPath`; scope to non-developer device groups first, then widen. Never exclude on `FileName` alone. |
| 4 | Buggy native modules, version manager mismatches, devs killing processes. | Keep `Crashes >= 2`; baseline per device for 14 days and alert on a step change. |

Run Query 3 as a custom detection rule (hourly, 1h lookback) after a week of baselining. Keep 1, 2 and 4 as scheduled hunts.

## Confidence

- CVE facts and fixed versions: **high**. Consistent across Rapid7, Help Net Security and Safe Security.
- Query 1: **medium-high** for nvm/Homebrew/Volta/asdf/fnm installs; **low** for official-pkg and Bun installs unless the hash lookup fills them in. Path layouts are from the tools' defaults, so check against your estate.
- Query 2: **medium** for what it finds, **low** for coverage (30-day install window only).
- Step 2b: **high**. It's the ground truth.
- Query 3: **medium**. Good generic RCE signal; the exclusion lists need tuning.
- Query 4: **low to medium**. Depends on MDE capturing file creates in `DiagnosticReports` in your config. Test with a deliberate crash on a lab Mac first.
- macOS exploitability: **judgement, low certainty**. No public macOS chain found; exposure is real.

## Not covered

- Electron apps embed Node, but I found no advisory saying Electron's bundled decoder is affected. Check Electron's advisories before assuming either way.
- Network-layer detection of crafted `Content-Encoding: br` traffic belongs at the WAF/proxy, not MDE.

## Sources

- [Rapid7 ETR](https://www.rapid7.com/blog/post/etr-cve-2026-111497-critical-out-of-bounds-write-in-the-node-js-brotli-decoder/)
- [Help Net Security, 27 Oct 2026](https://www.helpnetsecurity.com/2026/10/27/node2shell-broccoli2shell-vulnerability-cve-2026-111497/)
- [Safe Security technical write-up](https://safe.security/resources/blog/cve-2026-111497-inside-node2shell-and-the-brotli-decoder-flaw/)
- [OpenCVE record](https://app.opencve.io/cve/CVE-2026-111497)
- [F5 K000163902](https://my.f5.com/manage/s/article/K000163902)
