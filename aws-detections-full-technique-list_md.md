# AWS detections for the full technique list (CloudTrail and VPC Flow Logs)

Compiled 12 Oct 2026, grouped by tactic as listed. I wrote none of these; every entry is an existing public rule.

**Key**
- **SPL** = native Splunk (Splunk ESCU on research.splunk.com, or Anvilogic Forge).
- **Port** = a rule in another language that's easy to rewrite in SPL. *Easy* means a single CloudTrail event filter. *Medium* means first-seen or new-terms logic, which needs a baseline lookup. *Harder* means aggregation or correlation logic.
- **Direct** = the publisher tags the rule with that technique. **Adjacent** = the rule watches the same API calls, but the publisher maps it elsewhere (their tag is shown).
- CT = CloudTrail; FL = VPC Flow Logs. Unless stated, every rule below runs on CloudTrail management events.

Splunk, Elastic, Sigma and Datadog pages were opened to confirm tags and logic. Anvilogic and Panther were confirmed through Rulehound. For field mapping and Sigma conversion, see [aws-portable-detections-by-technique.md](aws-portable-detections-by-technique.md).

**Note on IDs:** some publishers have moved to newer ATT&CK numbering. For example, Splunk now tags CloudTrail tampering as T1685.002, and SigmaHQ uses the "defense-impairment" tactic. Older IDs in your list may appear under new numbers in recent rule versions.

## Coverage at a glance

| Tactic | Technique | Native SPL | Portable | Flow logs |
|---|---|---|---|---|
| Execution | T1648 Serverless Execution | Yes (Anvilogic) | Strong | None |
| Persistence | T1525 Implant Internal Image | Adjacent only | Good (Datadog direct) | None |
| Persistence / PrivEsc | T1546 Event Triggered Execution | None | Good (Elastic) | None |
| Persistence / CredAccess | T1556.007 Hybrid Identity | Adjacent only | Parent T1556 only | None |
| Persistence / CredAccess | T1556.009 Conditional Access Policies | None | None | None |
| PrivEsc | T1548 / T1548.005 | Adjacent only | Strong (Elastic) | None |
| Defense Impairment | T1578.001 Create Snapshot | Adjacent | 1 direct (Elastic, RDS) | None |
| Defense Impairment | T1578.004 Revert Cloud Instance | None | 1 direct (Elastic) | None |
| Defense Impairment | T1578.005 Modify Cloud Compute Configurations | **Yes (Splunk)** | Strong | None |
| CredAccess / Discovery | T1040 Network Sniffing | None | 1 direct (Elastic, traffic mirroring) | **None** |
| CredAccess | T1552.001 Credentials In Files | None | 1 direct (Elastic, needs S3 data events) | None |
| CredAccess | T1555.006 Cloud Secrets Management Stores | None | Good (Elastic direct, Datadog parent) | None |
| CredAccess | T1606 / .001 / .002 | None | Parent T1606 only | None |
| Discovery | T1082 System Information Discovery | None | 1 (Anvilogic, SQL) | None |
| Discovery | T1087 Account Discovery | Adjacent | Good (Elastic, Sigma) | None |
| Discovery | T1518 Software Discovery | None | 1 direct (Elastic) | None |
| Lateral Movement | T1550.004 Web Session Cookie | None | Adjacent only | None |
| Collection | T1213.006 Databases | None | 2 direct (Elastic) | None |
| Exfiltration | T1020.001 Traffic Duplication | None | Parent T1020 only (Elastic) | **None** |
| Impact | T1490 Inhibit System Recovery | **Yes (Splunk)** | Strong | None |
| Impact | T1491 / T1491.002 Defacement | None | 1 direct (Elastic) | None |
| Impact | T1496.002 Bandwidth Hijacking | Adjacent (flow logs) | Parent T1496 only | **Weak** |

**The flow-log result is the main finding.** Even for the three network techniques (T1040, T1020.001, T1496.002), no public rule on VPC Flow Logs is tagged to them. In AWS, sniffing and duplication show up as the Traffic Mirroring API call in CloudTrail, not as flow-log patterns. Flow logs only help with T1496.002 as a volume or destination anomaly, and the rules for that are generic. See Impact below.

---

## Execution

### T1648 Serverless Execution
Covered in the earlier lists. Best picks:
- **SPL:** [AWS Lambda CreateFunction](https://rulehound.com/rules/61a3de) (Anvilogic, Direct).
- **Port, Easy:** [AWS Lambda Function Created or Updated](https://www.elastic.co/guide/en/security/current/aws-lambda-function-created-or-updated.html), [Layer Added](https://www.elastic.co/guide/en/security/current/aws-lambda-layer-added-to-existing-function.html), [Layer Shared Externally](https://www.elastic.co/guide/en/security/current/aws-lambda-layer-shared-externally.html) (Elastic, Direct).
- **Port, Medium:** Elastic's unusual-principal and unusual-ASN `Invoke` rules (these need Lambda data events). Details are in [aws-portable-detections-by-technique.md](aws-portable-detections-by-technique.md#t1648-serverless-execution).

## Persistence

### T1525 Implant Internal Image
- **Port, Easy, Direct:** Datadog [New Private Repository Container Image detected in AWS ECR](https://docs.datadoghq.com/security/default_rules/aws-ecr-new-private-image/) and [New Public Repository Container Image](https://docs.datadoghq.com/security/default_rules/bdv-1hj-qoq/) (`PutImage`), plus SigmaHQ [ECS Task Definition That Queries The Credential Endpoint](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_ecs_task_definition_cred_endpoint_query/).
- **SPL, Adjacent:** Splunk ESCU [AWS ECR Container Upload Unknown User](https://research.splunk.com/cloud/300688e4-365c-4486-a065-7c884462b31d/) and [Outside Business Hours](https://research.splunk.com/cloud/d4c4d4eb-3994-41ca-a25e-a82d64e125bb/) (tagged T1204.003).

### T1546 Event Triggered Execution (also Privilege Escalation)
- **Port, Easy, Direct (Elastic):** [Lambda Event Source Mapping Creation](https://www.elastic.co/guide/en/security/current/aws-lambda-event-source-mapping-creation.html), [Function Policy Updated to Allow Public Invocation](https://www.elastic.co/guide/en/security/current/aws-lambda-function-policy-updated-to-allow-public-invocation.html), [... Cross-Account Invocation](https://www.elastic.co/guide/en/security/current/aws-lambda-function-policy-updated-to-allow-cross-account-invocation.html).
- **Gap:** nothing covers S3 notifications or EventBridge rules that target a Lambda.

### T1556.007 Hybrid Identity (also Credential Access)
- **Port, Easy, Parent T1556:** SigmaHQ [AWS Identity Center Identity Provider Change](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_sso_idp_change/); Datadog [IAM Identity Center SSO configuration updated](https://docs.datadoghq.com/security/default_rules/cloudtrail-aws-sso-update-configuration/).
- **SPL, Adjacent:** Splunk [AWS SAML Update identity provider](https://research.splunk.com/cloud/2f0604c6-6030-11eb-ae93-0242ac130002) (T1078).
- **Port, Adjacent:** Elastic [IAM SAML Provider Updated](https://www.elastic.co/guide/en/security/current/aws-iam-saml-provider-updated.html) and [Created](https://www.elastic.co/guide/en/security/current/aws-iam-saml-provider-created.html) (T1484.002).
- *Correction to the first list:* Splunk's "AWS SAML Access by Provider User and Principal" has since been removed.

### T1556.009 Conditional Access Policies (also Credential Access)
- **No direct rule anywhere.** The nearest proxies are policy-change rules: Splunk [AWS Create Policy Version to allow all resources](https://research.splunk.com/cloud/2a9b80d3-6340-4345-b5ad-212bf3d0dac4/) (SPL, T1078.004) and Elastic [IAM Permissions Boundary Modified or Removed](https://www.elastic.co/guide/en/security/current/aws-iam-permissions-boundary-modified-or-removed.html) (Easy, T1098).

## Privilege Escalation

### T1546 Event Triggered Execution
See Persistence.

### T1548 Abuse Elevation Control Mechanism / T1548.005 Temporary Elevated Cloud Access

| Rule | Source | Kind | Tags | Logic | Effort |
|---|---|---|---|---|---|
| [AWS EC2 Instance Profile Associated with Running Instance](https://detection.fyi/elastic/detection-rules/integrations/aws/privilege_escalation_ec2_instance_profile_associated_with_running_instance/) | Elastic | Port | T1548.005 | `AssociateIamInstanceProfile` / `ReplaceIamInstanceProfile`, excluding AWS service and SSM callers | Easy |
| [AWS STS GetFederationToken with AdministratorAccess](https://www.elastic.co/guide/en/security/current/aws-sts-getfederationtoken-with-administratoraccess-in-request.html) | Elastic | Port | T1548.005 | `GetFederationToken` with `AdministratorAccess` in the request | Easy |
| [AWS IAM Customer Managed Policy Version Created or Default Version Set](https://www.elastic.co/guide/en/security/current/aws-iam-customer-managed-policy-version-created-or-default-version-set.html) | Elastic | Port | T1548.005 | `CreatePolicyVersion` / `SetDefaultPolicyVersion` | Easy |
| [AWS STS AssumeRoot by Rare User and Member Account](https://www.elastic.co/guide/en/security/current/aws-sts-assumeroot-by-rare-user-and-member-account.html) | Elastic | Port | T1548.005 | First-seen `AssumeRoot` | Medium |
| [AWS STS Role Assumption by Service](https://www.elastic.co/guide/en/security/current/aws-sts-role-assumption-by-service.html) | Elastic | Port | T1548.005 | First-seen `AssumeRole` by an AWS service | Medium |
| [AWS STS Role Chaining](https://www.elastic.co/guide/en/security/current/aws-sts-role-chaining.html) / [by User](https://www.elastic.co/guide/en/security/current/aws-sts-role-assumption-by-user.html) | Elastic | Port | T1548 | First-seen `AssumeRole` patterns | Medium |
| [AWS STS AssumeRole Misuse](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_sts_assumerole_misuse/) / [GetSessionToken Misuse](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_sts_getsessiontoken_misuse/) | SigmaHQ | Port | T1548 | Simple STS filters (noisy) | Easy |
| [Cloud API Calls From Previously Unseen User Roles](https://research.splunk.com/cloud/2181ad1f-1e73-4d0c-9780-e8880482a08f) | Splunk | SPL | Adjacent (T1078) | New commands run by `AssumedRole` identities | n/a |

## Defense Impairment

### T1578.001 Create Snapshot
- **Port, Easy, Direct:** Elastic [AWS RDS DB Snapshot Created](https://www.elastic.co/guide/en/security/current/aws-rds-db-snapshot-created.html) (`CreateDBSnapshot`, `CreateDBClusterSnapshot`). Elastic marks it as a building-block rule, meaning it's intended as an input to other rules rather than an alert on its own.
- **SPL, Adjacent (T1537):** Splunk [AWS Exfiltration via EC2 Snapshot](https://research.splunk.com/cloud/ac90b339-13fc-4f29-a18c-4abbba1f2171) (the `CreateSnapshot`, `ModifySnapshotAttribute`, `DeleteSnapshot` chain) and [AWS EC2 Snapshot Shared Externally](https://research.splunk.com/cloud/2a9b80d3-6340-4345-b5ad-290bf3d222c4) (ASL version: [link](https://research.splunk.com/cloud/00af8f7f-e004-446b-9bba-2732f717ae27/)).
- **Port, Adjacent (T1537):** Datadog [AWS EBS Snapshot possible exfiltration](https://docs.datadoghq.com/security/default_rules/cloudtrail-aws-ebs-snapshot-possible-exfiltration/) (`CreateSnapshot` + `ModifySnapshotAttribute` within 15 minutes; Medium). Elastic [EC2 EBS Snapshot Shared or Made Public](https://detection.fyi/elastic/detection-rules/integrations/aws/exfiltration_ec2_ebs_snapshot_shared_with_another_account/).
- **Gap:** nothing is tagged T1578.001 for a plain EC2 `CreateSnapshot`.

### T1578.004 Revert Cloud Instance
- **Port, Easy, Direct:** Elastic [AWS RDS DB Instance Restored](https://detection.fyi/elastic/detection-rules/integrations/aws/defense_evasion_rds_instance_restored/) (`RestoreDBInstanceFromDBSnapshot` / `RestoreDBInstanceFromS3`).
- **Port, Adjacent:** SigmaHQ [Restore Public AWS RDS Instance](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_rds_public_db_restore/) (T1020; restore with `publiclyAccessible=true`).
- **Gap:** nothing covers EC2 reverts, such as `ReplaceRootVolume` or creating a volume from an old snapshot.

### T1578.005 Modify Cloud Compute Configurations

| Rule | Source | Kind | Tags | Logic | Effort |
|---|---|---|---|---|---|
| [Cloud Security Groups Modifications by User](https://research.splunk.com/cloud/cfe7cca7-2746-4bdf-b712-b01ed819b9de) | Splunk | **SPL** | T1578.005 | Change data model; 3-sigma outlier on security-group changes per user | n/a |
| [AWS EC2 Serial Console Access Enabled](https://detection.fyi/elastic/detection-rules/integrations/aws/defense_evasion_ec2_serial_console_access_enabled/) | Elastic | Port | T1578.005 | `EnableSerialConsoleAccess` | Easy |
| [AWS EC2 Route Table Modified or Deleted](https://detection.fyi/elastic/detection-rules/integrations/aws/persistence_ec2_route_table_modified_or_deleted/) | Elastic | Port | T1578.005 | First-seen user for `ReplaceRoute`, `DeleteRoute`, etc. | Medium |
| Lambda layer / function-policy / function-URL rules ([layer added](https://www.elastic.co/guide/en/security/current/aws-lambda-layer-added-to-existing-function.html), [public invoke](https://www.elastic.co/guide/en/security/current/aws-lambda-function-policy-updated-to-allow-public-invocation.html), [function URL public](https://www.elastic.co/guide/en/security/current/aws-lambda-function-url-created-with-public-access.html)) | Elastic | Port | T1578.005 | See T1648 / T1546 | Easy |
| [AWS EC2 Stop, Start, and User Data Modification Correlation](https://detection.fyi/elastic/detection-rules/integrations/aws/execution_ec2_stop_start_with_user_data_modification/) | Elastic | Port | T1578 (parent) | Stop, then `ModifyInstanceAttribute` userData, then Start on the same instance within 5 minutes | Harder |
| [AWS EC2 Startup Shell Script Change](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_ec2_startup_script_change/) | SigmaHQ | Port | Adjacent (T1059) | `ModifyInstanceAttribute` with `attribute=userData` | Easy |

## Credential Access

### T1040 Network Sniffing (also Discovery)
- **Port, Easy, Direct:** Elastic [AWS EC2 Full Network Packet Capture Detected](https://www.elastic.co/guide/en/security/current/aws-ec2-full-network-packet-capture-detected.html) (`CreateTrafficMirrorSession`; tagged T1040, T1020).
- **Flow logs:** none. Traffic Mirroring is the cloud-native way to sniff traffic, and it's a CloudTrail event. Flow logs record metadata only, so they don't reveal sniffing.

### T1552.001 Credentials In Files
- **Port, Easy, Direct:** Elastic [AWS S3 Credential File Retrieved from Bucket](https://detection.fyi/elastic/detection-rules/integrations/aws/credential_access_credentials_in_s3_bucket/) (`GetObject` on keys like `.env`, `credentials`, `.pem`). **This needs S3 data events enabled in CloudTrail.**
- **Port, Adjacent (T1552.005):** Elastic [AWS EC2 Unauthorized Admin Credential Fetch via Assumed Role](https://detection.fyi/elastic/detection-rules/integrations/aws/credential_access_aws_getpassword_for_ec2_instance/) (failed `GetPasswordData`; Medium).

### T1555.006 Cloud Secrets Management Stores

| Rule | Source | Tags | Logic | Effort |
|---|---|---|---|---|
| [First Time Seen AWS Secret Value Accessed in Secrets Manager](https://detection.fyi/elastic/detection-rules/integrations/aws/credential_access_new_terms_secretsmanager_getsecretvalue/) | Elastic | T1555.006 | First-seen `GetSecretValue` per user | Medium |
| [AWS Secrets Manager Rapid Secrets Retrieval](https://detection.fyi/elastic/detection-rules/integrations/aws/credential_access_rapid_secret_retrieval_attempts_from_secretsmanager/) | Elastic | T1555.006, T1213.006 | 20+ distinct secrets from one user (threshold) | Easy |
| [Multiple Cloud Secrets Accessed by Source Address](https://detection.fyi/elastic/detection-rules/cross-platform/credential_access_multi_could_secrets_via_api/) | Elastic | T1555.006 | One IP pulling secrets across AWS, Azure, GCP and Kubernetes | Harder |
| [Possible secret enumeration in multiple regions and secret retrieval](https://docs.datadoghq.com/security/default_rules/def-000-9fr) | Datadog | T1555 | `ListSecrets` across regions, then `GetSecretValue` | Medium |
| [User enumerated AWS Secrets Manager - Anomaly](https://docs.datadoghq.com/security/default_rules/cloudtrail-aws-user-enumerated-secrets-anomaly-detection/) | Datadog | T1555 | Anomalous `GetSecretValue` AccessDenied count per user | Medium |
| [SecretsManager secret retrieved from AWS CloudShell](https://docs.datadoghq.com/security/default_rules/cloudtrail-aws-secretsmanager-getsecretvalue-cloudshell) | Datadog | T1555 | `GetSecretValue` from CloudShell | Easy |

No native SPL found.

### T1556.007 / T1556.009
See Persistence.

### T1606 Forge Web Credentials / T1606.001 Web Cookies / T1606.002 SAML Tokens
- **Port, Harder, Parent T1606:** Elastic [AWS GetFederationToken Followed by Console Login via Federation Exchange](https://detection.fyi/elastic/detection-rules/integrations/aws/credential_access_get_federation_token_followed_by_console_login_via_federation_exchange/). It's a sequence of `GetFederationToken`, then `GetSigninToken`, then `ConsoleLogin` from the same IP within 2 minutes. In SPL that's `transaction` or `streamstats`.
- **Adjacent (T1550.001):** SigmaHQ [AWS Console GetSigninToken Potential Abuse](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_console_getsignintoken/) (Easy) and its Panther equivalent ([Rulehound](https://rulehound.com/rules/e570af)).
- **T1606.002, my judgement:** forged SAML is detected at the IdP, or by `AssumeRoleWithSAML` with no matching IdP sign-in. No public CloudTrail rule does that correlation. The closest is SigmaHQ [AWS Suspicious SAML Activity](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_susp_saml_activity/) (T1548/T1550.001; `AssumeRoleWithSAML` or `UpdateSAMLProvider`).
- **T1606.001:** nothing found.

## Discovery

### T1040 Network Sniffing
See Credential Access.

### T1082 System Information Discovery
- **Port, Direct (one tag among three):** Anvilogic [AWS Logging Enumeration](https://rulehound.com/rules/da954c) (T1580, T1082, T1526). Written in Snowflake SQL rather than SPL, but it's a simple event-list filter.
- No other AWS CloudTrail rule tagged T1082 was found. Publishers tag cloud discovery as T1580 or T1526 instead, for example Splunk [AWS Excessive Security Scanning](https://research.splunk.com/cloud/1fdd164a-def8-4762-83a9-9ffe24e74d5a/) (SPL, T1526, more than 50 distinct Describe/List/Get calls).

### T1087 Account Discovery

| Rule | Source | Kind | Tags | Logic | Effort |
|---|---|---|---|---|---|
| [AWS Discovery API Calls via CLI from a Single Resource](https://detection.fyi/elastic/detection-rules/integrations/aws/discovery_multiple_discovery_api_calls_via_cli/) | Elastic | Port | T1087.004 | More than 5 distinct Describe/Get/List actions from one ARN in 10 seconds | Medium |
| [AWS Account Discovery By Rare User](https://detection.fyi/elastic/detection-rules/integrations/aws/discovery_organization_discovery_by_rare_user/) | Elastic | Port | T1087.004 | First-seen Organizations or IAM account-discovery calls | Medium |
| [AWS EC2 Role GetCallerIdentity from New Source AS Organization](https://detection.fyi/elastic/detection-rules/integrations/aws/discovery_new_terms_sts_getcalleridentity_ec2_role_new_source_as/) | Elastic | Port | T1087.004 | EC2 role credentials used for `GetCallerIdentity` from a new ASN (catches stolen instance creds) | Medium |
| [AWS STS GetCallerIdentity Enumeration Via TruffleHog](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_sts_getcalleridentity_trufflehog/) | SigmaHQ | Port | T1087.004 | `GetCallerIdentity` with a TruffleHog user agent | Easy |
| [AWS IAM AccessDenied Discovery Events](https://research.splunk.com/cloud/3e1f1568-9633-11eb-a69c-acde48001122/) | Splunk | SPL | Adjacent (T1580) | 5 or more AccessDenied per hour per IP/user | n/a |

### T1518 Software Discovery
- **Port, Medium, Direct:** Elastic [AWS SSM Inventory Reconnaissance by Rare User](https://detection.fyi/elastic/detection-rules/integrations/aws/discovery_ssm_inventory_reconnaissance/) (first-seen `GetInventory`, `ListInventoryEntries`, etc.).

## Lateral Movement

### T1550.004 Web Session Cookie
- **No direct rule found.** Console session cookies are used after authentication and don't generate distinctive CloudTrail events.
- **Adjacent:** Elastic [AWS Access Token Used from Multiple Addresses](https://detection.fyi/elastic/detection-rules/integrations/aws/initial_access_iam_session_token_used_from_multiple_addresses/) (T1078.004; one access key from many IPs, cities and ASNs in 30 minutes; Harder) and [AWS EC2 Instance Console Login via Assumed Role](https://detection.fyi/elastic/detection-rules/integrations/aws/lateral_movement_ec2_instance_console_login/) (T1550.001; Easy).

## Collection

### T1213.006 Databases
- **Port, Easy, Direct:** Elastic [AWS RDS Snapshot Export](https://www.elastic.co/guide/en/security/current/aws-rds-snapshot-export.html) (`StartExportTask`) and [AWS Secrets Manager Rapid Secrets Retrieval](https://detection.fyi/elastic/detection-rules/integrations/aws/credential_access_rapid_secret_retrieval_attempts_from_secretsmanager/) (also tagged T1555.006).
- **Gap:** nothing covers DynamoDB `ExportTableToPointInTime` or Redshift `UNLOAD`.

## Exfiltration

### T1020.001 Traffic Duplication
- **Port, Easy, Parent T1020:** Elastic [AWS EC2 Full Network Packet Capture Detected](https://www.elastic.co/guide/en/security/current/aws-ec2-full-network-packet-capture-detected.html) (`CreateTrafficMirrorSession`). This is exactly what .001 means in AWS, even though the rule carries the parent tag.
- **Flow logs:** none. A mirror target is visible in flow logs as VXLAN traffic (UDP 4789) to the target ENI. That would be a hunt idea, not a published rule.

## Impact

### T1490 Inhibit System Recovery

| Rule | Source | Kind | Tags | Logic | Effort |
|---|---|---|---|---|---|
| [AWS Disable Bucket Versioning](https://research.splunk.com/cloud/657902a9-987d-4879-a1b2-e7a65512824b) | Splunk | **SPL** | T1490 | `PutBucketVersioning` with `Status=Suspended` | n/a |
| [ASL AWS Disable Bucket Versioning](https://research.splunk.com/cloud/f32598bb-fa5f-4afd-8ab3-0263cc28efbc) | Splunk | **SPL** (ASL) | T1490 | Same, on Security Lake | n/a |
| [AWS RDS Snapshot Deleted](https://detection.fyi/elastic/detection-rules/integrations/aws/impact_rds_snapshot_deleted/) | Elastic | Port | T1490 | `DeleteDBSnapshot`, `DeleteDBClusterSnapshot`, or `ModifyDBInstance` with `backupRetentionPeriod=0` | Easy |
| [AWS Backup Vault Deleted or Vault Lock Removed](https://detection.fyi/elastic/detection-rules/integrations/aws/impact_backup_vault_deleted_or_lock_removed/) | Elastic | Port | T1490 | `DeleteBackupVault`, `DeleteBackupVaultLockConfiguration` | Easy |
| [AWS Backup Recovery Point Deleted](https://detection.fyi/elastic/detection-rules/integrations/aws/impact_backup_recovery_point_deleted/) | Elastic | Port | T1490 | `DeleteRecoveryPoint` | Easy |
| [AWS S3 Object Versioning Suspended](https://detection.fyi/elastic/detection-rules/integrations/aws/impact_s3_object_versioning_disabled/) | Elastic | Port | T1490 | Same as the Splunk rule | Easy |
| [AWS S3 Bucket Versioning Disable](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_disable_bucket_versioning/) | SigmaHQ | Port | T1490 | Same | Easy |

### T1491 Defacement / T1491.002 External Defacement
- **Port, Medium, Direct:** Elastic [AWS S3 Static Site JavaScript File Uploaded](https://detection.fyi/elastic/detection-rules/integrations/aws/impact_s3_static_site_js_file_uploaded/) (T1491.002). It flags `PutObject` of `.js` files under `static/js/` by IAM users or roles, and needs S3 data events. It's written in ES|QL, but the logic is a simple filter.

### T1496.002 Bandwidth Hijacking
- **No rule anywhere is tagged .002.**
- **Flow logs, SPL, untagged:** Splunk [Detect Spike in blocked Outbound Traffic from your AWS](https://research.splunk.com/cloud/d3fffa37-492f-487b-a35d-c60fcb2acf01/) (experimental, `aws:cloudwatchlogs:vpcflow`). This is the only public flow-log SPL I found.
- **Flow logs, other:** Datadog [Potential cryptomining detected through IP callback](https://docs.datadoghq.com/security/default_rules/o2v-dml-922/) (T1496; matches the client IP against mining-pool lists, so it works on any log with IPs, including flow logs). Turbot's [Tailpipe AWS VPC Flow Log Detections mod](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-aws-vpc-flow-log-detections/benchmarks/detection.large_data_transfer) publishes SQL flow-log detections (large data transfer, high packet traffic, unusual protocols) with an ATT&CK v16.1 benchmark. That hub page renders client-side, so I couldn't confirm the per-rule technique tags.
- **CloudTrail, Port, Parent T1496:** Elastic [AWS Potential Cryptomining via ECS Task Definition Deployment](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/aws/impact_ecs_cryptomining_task_definition_deployment) (compute hijacking rather than bandwidth; ES|QL; Harder).

---

## Gaps with nothing public in any source
- T1556.009 Conditional Access Policies
- T1606.001 Web Cookies
- T1550.004 Web Session Cookie
- T1546 via S3 notifications or EventBridge
- T1578.001 on EC2 (only RDS is covered)
- T1578.004 on EC2 (only RDS is covered)
- Any VPC Flow Logs rule tagged T1040, T1020.001 or T1496.002
