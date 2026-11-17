# Where queries go in this repo

| Folder | Put here |
|---|---|
| `Threat Hunting/` | Proactive hunts for a threat, CVE, malware or technique. Usually 30d lookback. |
| `Detection/` | Tight, low-noise queries meant to run on a schedule or become custom detection rules. |
| `Investigation/` | Triage queries for a specific user, device, IP or alert, parameterised with `let` inputs. |
| `Baselines/` | "What is normal" queries: prevalence, frequency, first-seen. |
| `Templates/` | Reusable skeletons (e.g. IOC hunt) with placeholder inputs. |
| `Docs/` | Runbooks, write-ups and markdown notes (not queries). |

## File naming

- Extension: `.kql` for queries, `.md` for docs.
- Title Case words separated by spaces; use ` - ` to separate parts.
- Lead with the most identifying thing:
  - CVE: `CVE-2025-56383 - Notepad++ DLL Hijacking.kql`
  - Technique: `LOLBAS - PowerShell AV Exclusion Commands.kql`
  - Malware/campaign: `ClickFix - Multi-Stage Attack Chain.kql`
  - Investigation: `Entra ID - User Authentication Timeline.kql`
- Avoid characters that cause trouble in paths: `/ \ : * ? " < > |` and non-ASCII dashes (use a normal `-`).
