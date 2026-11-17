---
name: kql-query
description: Build a new KQL query for Microsoft Defender XDR Advanced Hunting (or Sentinel) from a plain-English request, a CVE/campaign name, or a list of IOCs. Researches the threat on the web when one is named, drafts a fully commented query, reviews it in several passes, saves it to the right folder in this repo, and commits and pushes it. Use when the user asks to write, create, build or hunt with a KQL query, or invokes /kql-query.
---

# KQL Query Builder

You are helping a SOC analyst turn an idea into a well-documented, reviewed KQL query and get it into this Git repo. The user is new to Git, so explain any Git step in one plain sentence as you do it.

Follow the six stages below in order. Do not skip the review stage.

---

## Stage 1: Understand the request

Work out what kind of input you were given. It will vary:

| Input looks like | What to do |
|---|---|
| A CVE ID, malware family, threat actor or named campaign | Go to Stage 2 (research) before writing anything. |
| A list of hashes, IPs, domains or URLs | Start from `references/templates/ioc-hunt.kql`. Ask only where the IOCs came from (for the References line). |
| A behaviour ("PowerShell downloading from paste sites") | Map it to MITRE ATT&CK yourself, pick the tables, go to Stage 3. |
| An investigation ("show me everything user X did around 10:00") | It is an Investigation query: parameterise the user/device/time with `let` at the top. |
| A pasted article, alert or report | Pull out the IOCs and TTPs from it, then treat it as the matching row above. |

Defaults (don't ask about these unless the request contradicts them):
- Platform: **Defender XDR Advanced Hunting** (uses `Timestamp`). Only use Sentinel tables / `TimeGenerated` if the user says Sentinel or the data only exists there (e.g. `SigninLogs`, `AuditLogs`, `SecurityEvent`, Syslog).
- Lookback: 30d for hunting (Advanced Hunting keeps 30 days), 1h-24h for detection-style queries, parameterised for investigations.

Only ask the user a question if you truly cannot proceed (e.g. "hunt for the thing from yesterday's email" with no detail). Ask at most 2-3 short questions at once.

## Stage 2: Research (only for a named CVE, malware, actor or campaign)

Search the web before drafting. Aim for 2-4 good sources, preferring: the vendor advisory, NVD/CISA KEV, Microsoft Threat Intelligence / MSRC, and reputable vendor research (Mandiant, Unit 42, Talos, Huntress, Red Canary, etc.).

Collect:
- **What it is**: affected product and versions, how exploitation or infection works.
- **TTPs**: the observable behaviours (processes, command lines, file paths, registry keys, network patterns), with MITRE technique IDs.
- **IOCs**: hashes, domains, IPs, URLs, file names. Note the date and source of each list, because IOCs go stale fast.

Then tell the user in a short summary (5-10 lines) what you found and which behaviours you plan to hunt for, with source links. Prefer **behaviour-based** logic (TTPs) as the main query and IOCs as a supporting section, because IOCs change and behaviours don't.

Never invent IOCs. If you cannot find any, say so and build the behavioural hunt only.

## Stage 3: Draft the query

Read `references/style-guide.md` and `references/defender-schema.md` before writing. Key rules:

1. Start with the **header block** from `references/header-template.kql`, fully filled in.
2. Put every tunable value in a `let` at the top under a `// ---- Inputs ----` heading, each with an inline comment.
3. **Comment throughout.** Every logical step gets a comment line above it saying *what* it does and *why*, in plain English an L1 analyst would follow. Inline comments explain non-obvious values (e.g. why a LogonType is excluded).
4. Filter on time first, then on the most selective column, before any `extend`, `join` or `parse`.
5. End with a `project` of analyst-useful columns in a sensible order (time, device, user, what happened, evidence, parent process) and a `sort` or `summarize`.

## Stage 4: Review (three passes, mandatory)

Review the draft yourself in three separate passes. In each pass, write down what you found, then fix it. Keep the passes distinct; don't merge them.

**Pass 1: Correctness**
- Every table and column exists in Defender Advanced Hunting (check `references/defender-schema.md`; if a column isn't listed there and you aren't certain, search Microsoft Learn for the table's schema page).
- `Timestamp` vs `TimeGenerated` is consistent with the platform.
- Syntax: balanced brackets, `let` statements end with `;`, `dynamic([...])` used for lists, operators are valid (`has_any`, `in~`, `matches regex`, etc.).
- Join kinds are explicit (`kind=inner`, `kind=leftouter`) and join keys exist on both sides.
- Data types match (e.g. `tostring()` on dynamic fields before comparing, `toint()` on ports from `AdditionalFields`).

**Pass 2: Detection logic**
- Does it actually catch the behaviour/TTP described? Walk through one realistic malicious example and confirm it would match.
- False positives: what legitimate software or admin activity would match? Add exclusions as `let` lists with comments, or note them in the header's Tuning section.
- Easy evasions: renamed binaries (use `ProcessVersionInfoOriginalFileName` where relevant), case changes (use `=~`, `in~`, `has` which are case-insensitive), alternate paths, encoded command lines.
- MITRE mapping in the header is accurate.

**Pass 3: Performance, style and readability**
- Time filter first; `has`/`has_any` preferred over `contains`; no `search *` or unfiltered `union *`.
- Joins: smaller table on the left, both sides pre-filtered and `project`ed down.
- Matches `references/style-guide.md`: header complete, inputs block, comments on every step, readable indentation.
- Output columns are useful and not excessive.

After Pass 3, if you changed anything significant, run Pass 1 again on the changed parts. Then show the user:
- The final query in a ```kql code block.
- A short review summary: what each pass changed (2-5 bullets in total) and any remaining caveats (e.g. "not tested against live data").

Ask: **"Happy with this? I'll save it and push it to GitHub."** Wait for a yes (or changes) before Stage 5.

## Stage 5: Save to the repo

Pick the folder from `references/repo-layout.md` and name the file per the naming rule there (Title Case, ` - ` separators, `.kql` extension). Tell the user the path you chose.

Check nothing with the same name or purpose already exists (`ls`/grep the folder). If something close exists, ask whether to update it or create a new one.

## Stage 6: Commit and push (explain as you go)

The user is new to Git. Use these steps and give each a one-line plain-English explanation.

1. **Branch.** If the session's system instructions name a development branch, use that one. Otherwise create one: `git checkout -b kql/<short-slug>` (e.g. `kql/cve-2025-56383-notepadpp`).
   Explain: *"A branch is a separate copy of the repo where this change sits until you approve it, so `main` stays clean."*
2. **Commit.** `git add "<path>"` then `git commit -m "Add <Title> (<type>)"` with a short body listing MITRE IDs and data sources.
   Explain: *"A commit is a saved snapshot of the change with a message saying what it is."*
3. **Push.** `git push -u origin <branch>` (retry up to 4 times on network errors).
   Explain: *"Push uploads the branch to GitHub."*
4. **Pull request.** Ask the user whether to open a pull request into `main`. If yes, open it with a description containing: what the query hunts for, MITRE IDs, data sources, references, and the review summary.
   Explain: *"A pull request is GitHub's 'please review and merge this' page. When you click Merge on it, the query lands in `main`."*

Never push directly to `main` unless the user explicitly says so for that change.

Finish with: the file path, the branch, and the PR link (if created).
