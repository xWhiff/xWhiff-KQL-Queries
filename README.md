````markdown
# 🛡️ KQL Threat Hunting & Triage Queries

A curated collection of **Kusto Query Language (KQL)** queries for **threat hunting, incident response, detection validation, and security triage** across Microsoft Sentinel, Microsoft Defender XDR, Azure Monitor, and other platforms that support KQL.

The goal of this repository is to provide practical, well-documented queries that help security analysts quickly investigate suspicious activity, validate detections, and improve hunting capabilities.

---

## 📋 Contents

- Threat Hunting
- Incident Triage
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command & Control
- Exfiltration
- Impact
- Microsoft Defender XDR
- Microsoft Sentinel
- Azure AD / Entra ID
- Microsoft 365
- Azure Activity
- Device Investigations
- Identity Investigations
- Email Investigations
- IOC Hunting
- Sigma Conversions
- Detection Validation

---

## 🎯 Purpose

This repository is intended to:

- Speed up investigations
- Provide reusable hunting queries
- Reduce repetitive analyst work
- Share detection logic
- Improve SOC efficiency
- Help junior analysts learn KQL
- Serve as a personal knowledge base

---

## 📂 Repository Structure

```
.
├── README.md
├── Threat Hunting
│   ├── Initial Access
│   ├── Execution
│   ├── Persistence
│   ├── Privilege Escalation
│   ├── Defense Evasion
│   ├── Credential Access
│   ├── Discovery
│   ├── Lateral Movement
│   ├── Collection
│   ├── Command and Control
│   ├── Exfiltration
│   └── Impact
│
├── Triage
│   ├── Identity
│   ├── Endpoint
│   ├── Email
│   ├── Cloud
│   └── Network
│
├── IOC Hunting
│
├── Defender XDR
│
├── Microsoft Sentinel
│
├── Azure
│
├── Entra ID
│
├── Detection Validation
│
└── Sigma Conversions
```

---

## 📝 Query Format

Each query should include:

```kusto
// Name:
// Description:
// MITRE ATT&CK:
// Data Sources:
// Required Tables:
// Author:
// Last Updated:

<query>
```

Example:

```kusto
// Name:
// Suspicious PowerShell Downloads
//
// Description:
// Detects PowerShell downloading content from the internet.
//
// MITRE ATT&CK:
// T1059.001
//
// Data Sources:
// Microsoft Defender XDR
//
// Required Tables:
// DeviceProcessEvents
//
// Author:
// Your Name

DeviceProcessEvents
| where ProcessCommandLine has_any ("Invoke-WebRequest","DownloadString","curl","wget")
```

---

## 🏷️ Naming Convention

Use descriptive filenames.

Examples:

```
Detect-PowerShell-Download.kql
Detect-RDP-BruteForce.kql
Find-New-Admin-Accounts.kql
Hunt-Suspicious-ScheduledTasks.kql
Find-Encoded-PowerShell.kql
```

---

## 📌 MITRE ATT&CK Mapping

Where applicable, queries should reference the associated ATT&CK technique.

Example:

| Technique | Description |
|-----------|-------------|
| T1059 | Command and Scripting Interpreter |
| T1105 | Ingress Tool Transfer |
| T1078 | Valid Accounts |
| T1003 | OS Credential Dumping |
| T1021 | Remote Services |

---

## 💡 Contributions

Contributions are welcome!

When submitting queries:

- Include comments
- Explain the purpose
- Reference ATT&CK where appropriate
- Keep queries performant
- Avoid unnecessary joins
- Test before submitting

---

## ⚠️ Disclaimer

These queries are provided **as-is** without warranty.

Always validate queries in your own environment before using them in production.

---

## 📚 Useful Resources

- Microsoft Learn - KQL Documentation
- Microsoft Sentinel Documentation
- Microsoft Defender XDR Advanced Hunting
- MITRE ATT&CK
- Kusto Query Language Documentation

---

## ⭐ Support

If you find this repository useful:

- ⭐ Star the repository
- 🍴 Fork it
- 🛠️ Submit improvements
- 📢 Share with the community

---

Happy Hunting! 🎯
```
````
