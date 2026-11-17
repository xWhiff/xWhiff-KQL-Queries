# 🛡️ KQL Threat Hunting & Triage Queries

A curated collection of **Kusto Query Language (KQL)** queries for **threat hunting, incident response, detection validation, and security triage** across Microsoft Sentinel, Microsoft Defender XDR, Azure Monitor, and other platforms that support KQL.

The goal of this repository is to provide practical, well-documented queries that help security analysts quickly investigate suspicious activity, validate detections, and improve hunting capabilities.

## 📁 Layout

| Folder | What's in it |
|---|---|
| `Threat Hunting/` | Proactive hunts for a threat, CVE, malware family or technique. |
| `Detection/` | Tight, low-noise queries meant to run on a schedule or become custom detection rules. |
| `Investigation/` | Triage queries for a specific user, device, IP or alert. |
| `Baselines/` | "What is normal" queries: prevalence, frequency, first-seen. |
| `Templates/` | Reusable skeletons (e.g. IOC hunt) with placeholder inputs. |
| `Docs/` | Runbooks and write-ups. |

Files are named `<Threat or Topic> - <What it does>.kql`, e.g. `CVE-2025-56383 - Notepad++ DLL Hijacking.kql`.

Happy Hunting! 🎯
