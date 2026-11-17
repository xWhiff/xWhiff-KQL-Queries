# Defender XDR Advanced Hunting: quick schema reference

Not exhaustive. If a column you need isn't here and you aren't sure it exists, check the table's page on Microsoft Learn ("<TableName> table in the advanced hunting schema").

## Platform gotchas

- Advanced Hunting uses **`Timestamp`**. The same tables in Sentinel (via the XDR connector) use **`TimeGenerated`**. Pick one per query.
- Advanced Hunting keeps **30 days** of data.
- Most Device* tables share `Timestamp, DeviceId, DeviceName, ActionType, ReportId` and the `InitiatingProcess*` family (`InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `InitiatingProcessFolderPath`, `InitiatingProcessSHA256`, `InitiatingProcessAccountName`, `InitiatingProcessParentFileName`, `InitiatingProcessId`).
- Custom detection rules built from a query need `Timestamp`, `ReportId` and an entity column such as `DeviceId` in the output.
- `AdditionalFields` is a JSON string/dynamic: use `parse_json(AdditionalFields).<key>` and cast with `tostring()`/`toint()`.
- Useful functions: `FileProfile(SHA1|SHA256, max)` adds `GlobalPrevalence`, `GlobalFirstSeen`, `Signer`, `IsCertificateValid` etc.; `DeviceFromIP(ip, time)` maps an IP to a device; `AssignedIPAddresses(device, time)` the reverse.

## Endpoint (Defender for Endpoint)

| Table | Key columns |
|---|---|
| DeviceProcessEvents | FileName, FolderPath, ProcessCommandLine, ProcessVersionInfoOriginalFileName, ProcessIntegrityLevel, SHA1, SHA256, MD5, AccountName, AccountDomain, AccountSid, ProcessId |
| DeviceNetworkEvents | RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort, Protocol, ActionType (ConnectionSuccess, ConnectionFailed, InboundConnectionAccepted, ...) |
| DeviceFileEvents | FileName, FolderPath, SHA1, SHA256, MD5, FileSize, ActionType (FileCreated, FileModified, FileRenamed, FileDeleted), PreviousFileName, FileOriginUrl, FileOriginReferrerUrl |
| DeviceRegistryEvents | RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryValueData, ActionType (RegistryValueSet, RegistryKeyCreated, ...) |
| DeviceImageLoadEvents | FileName, FolderPath, SHA1, SHA256 (the loaded DLL) + InitiatingProcess* (the loader) |
| DeviceLogonEvents | AccountName, AccountDomain, LogonType, RemoteIP, RemoteDeviceName, IsLocalAdmin, ActionType (LogonSuccess, LogonFailed) |
| DeviceEvents | ActionType (very many: AntivirusDetection, PowerShellCommand, ScheduledTaskCreated, ...), AdditionalFields, FileName, ProcessCommandLine |
| DeviceInfo | OSPlatform, OSVersion, DeviceType, MachineGroup, PublicIP, IsInternetFacing, OnboardingStatus |
| DeviceNetworkInfo | IPAddresses (dynamic), MacAddress, NetworkAdapterName |
| DeviceFileCertificateInfo | SHA1, Signer, Issuer, IsSigned, IsTrusted, CertificateSerialNumber |

## Email (Defender for Office 365)

| Table | Key columns |
|---|---|
| EmailEvents | NetworkMessageId, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes, EmailDirection |
| EmailAttachmentInfo | NetworkMessageId, FileName, FileType, SHA256, SenderFromAddress, RecipientEmailAddress |
| EmailUrlInfo | NetworkMessageId, Url, UrlDomain, UrlLocation |
| UrlClickEvents | Url, AccountUpn, ActionType, IsClickedThrough, NetworkMessageId, IPAddress |

## Identity and cloud apps

| Table | Key columns |
|---|---|
| IdentityLogonEvents | AccountUpn, AccountName, ActionType, LogonType, Protocol, IPAddress, DeviceName, Application, FailureReason |
| IdentityQueryEvents | ActionType, QueryType, QueryTarget, Query, AccountName, DeviceName |
| IdentityDirectoryEvents | ActionType, TargetAccountUpn, AdditionalFields |
| EntraIdSignInEvents (formerly AADSignInEventsBeta) | AccountUpn, Application, IPAddress, Country, ErrorCode, RiskLevelDuringSignIn, ConditionalAccessStatus, LogonType |
| CloudAppEvents | ActionType, Application, AccountDisplayName, AccountObjectId, IPAddress, ObjectName, RawEventData |

## Alerts

| Table | Key columns |
|---|---|
| AlertInfo | AlertId, Title, Severity, Category, ServiceSource, DetectionSource, AttackTechniques |
| AlertEvidence | AlertId, EntityType, EvidenceRole, DeviceId, FileName, SHA256, RemoteIP, AccountUpn |

## Sentinel-only tables (use TimeGenerated)

SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, SecurityEvent, Syslog, CommonSecurityLog, OfficeActivity, AzureActivity.
