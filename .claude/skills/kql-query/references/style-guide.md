# KQL Style Guide for this repo

## Layout of every query

```kql
// ===== header block (references/header-template.kql) =====

// ---- Inputs ----
let lookback = 30d;                                   // how far back to search
let SuspiciousTools = dynamic(["certutil.exe", "bitsadmin.exe"]);  // LOLBins to watch
let ExcludedDevices = dynamic([]);                    // add noisy build servers here

// ---- Step 1: Find the suspicious process launches ----
// Look for the tools above being started with a URL on the command line,
// which is how they are typically abused to download payloads.
let Downloads =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)                 // time filter first for speed
    | where FileName in~ (SuspiciousTools)
    | where ProcessCommandLine has_any ("http://", "https://")
    | where DeviceName !in~ (ExcludedDevices);

// ---- Step 2: Add context from the parent process ----
// ...

// ---- Output ----
// One row per suspicious launch, newest first.
Downloads
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by Timestamp desc
```

## Rules

- **Comments**
  - `// ---- Section name ----` headings for Inputs, each Step, and Output.
  - One or two comment lines above each step: what it does and why, in plain English.
  - Inline `//` comments for magic values (LogonType numbers, ports, thresholds, regexes).
  - Write for an L1 analyst who knows the basics of KQL but not this threat.
- **Inputs**: every value someone might change goes in a `let` at the top. Variable names are `camelCase` for scalars (`lookback`, `alertTime`) and `PascalCase` for lists and sub-queries (`SuspiciousTools`, `Downloads`).
- **Case**: prefer case-insensitive operators (`=~`, `in~`, `has`, `has_any`) for file names, command lines and accounts.
- **Indentation**: 4 spaces inside `let` sub-queries and `union` branches; one operator per line.
- **Multi-table hunts**: build each table's hunt as its own `let`, give it a `Table = "<name>"` column, then `union isfuzzy=true` them so a missing table doesn't break the query.
- **IOCs**: always in a `dynamic([...])` list at the top, with a comment naming the source and date.
- **Output**: always finish with `project` and either `sort by Timestamp desc` or a `summarize` that gives counts, first/last seen and example values (`take_any`, `make_set(..., 10)`).
- **No** `search *`, `union *`, or `contains` when `has` works.
