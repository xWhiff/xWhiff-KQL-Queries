# Portable AWS detections (non-SPL) by MITRE technique

Compiled 12 Oct 2026. This is the follow-up to [aws-spl-detections-by-technique.md](aws-spl-detections-by-technique.md). It lists public Elastic, SigmaHQ, Datadog, Panther and Microsoft Sentinel analytics for AWS CloudTrail whose logic is simple enough to rewrite in SPL. None of them were written by me. Every Elastic, Sigma and Datadog page was opened to confirm the ATT&CK tags and logic. Panther entries were confirmed through the Rulehound index.

**Port effort**
- **Easy**: a single event filter (`eventSource` + `eventName`, perhaps a `requestParameters` match). This becomes one `search` line on `sourcetype=aws:cloudtrail`.
- **Medium**: an Elastic `new_terms` rule, meaning "first time this user/value has been seen in N days". In Splunk that means a baseline lookup (`stats earliest(_time) by ...` + `outputlookup`) or the ESCU "previously seen" pattern.
- **Harder**: ES|QL aggregation or multi-step logic. It ports, but needs real thought.

**Field mapping for Elastic to the Splunk Add-on for AWS (CloudTrail)**

| Elastic | Splunk |
|---|---|
| `event.provider` | `eventSource` |
| `event.action` | `eventName` |
| `event.outcome: success` | no `errorCode` (Splunk TA also normalises `errorCode=success`) |
| `aws.cloudtrail.user_identity.type` | `userIdentity.type` |
| `aws.cloudtrail.request_parameters` | `requestParameters.*` |
| `user_agent.original` | `userAgent` |
| `source.as.organization.name` | needs an ASN lookup (`iplocation` doesn't give ASN) |

Sigma rules can be converted directly with `sigma-cli` and the `splunk` backend, using the AWS CloudTrail pipeline.

## Summary

| Technique | Directly tagged, easy to port | Note |
|---|---|---|
| T1648 Serverless Execution | 5 Elastic (3 easy, 2 medium, 1 harder) | Good coverage |
| T1525 Implant Internal Image | 2 Datadog, 1 Sigma | Good. Datadog maps ECR `PutImage` straight to T1525 |
| T1546 Event Triggered Execution | 3 Elastic | Good. Lambda event-source mappings and permission backdoors |
| T1556.007 Hybrid Identity | None tagged .007 | Use the T1556 / T1484.002 federation rules below |
| T1556.009 Conditional Access Policies | None | Genuine gap in every source checked |
| T1548 Abuse Elevation Control Mechanism | 3 Elastic, 3 Sigma | |
| T1548.005 Temporary Elevated Cloud Access | 4 Elastic | Good. AssumeRoot, GetFederationToken, policy versions |
| VPC Flow Logs (any technique above) | None | Still none. These are control-plane techniques |

---

## T1648 Serverless Execution

| Rule | Source | Tags | Logic | Port |
|---|---|---|---|---|
| [AWS Lambda Function Created or Updated](https://www.elastic.co/guide/en/security/current/aws-lambda-function-created-or-updated.html) | Elastic | T1648 | `lambda.amazonaws.com` `CreateFunction*` or `UpdateFunctionCode*`, success, excluding Terraform/Pulumi user agents | Easy |
| [AWS Lambda Layer Added to Existing Function](https://www.elastic.co/guide/en/security/current/aws-lambda-layer-added-to-existing-function.html) | Elastic | T1648, T1578.005 | Lambda call adding a layer to an existing function, success (check the exact `eventName` on the page) | Easy |
| [AWS Lambda Layer Shared Externally](https://www.elastic.co/guide/en/security/current/aws-lambda-layer-shared-externally.html) | Elastic | T1648, T1578.005 | `AddLayerVersionPermission*`, success | Easy |
| [AWS Lambda Function Invoked by an Unusual Principal](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/aws/execution_lambda_function_invoked_by_unusual_principal) | Elastic | T1648 | new_terms on the principal for `Invoke*` (needs Lambda **data events** in CloudTrail) | Medium |
| [AWS Lambda Function Invoked from an Unusual Source ASN](https://www.elastic.co/guide/en/security/current/aws-lambda-function-invoked-from-an-unusual-source-asn.html) | Elastic | T1648 | new_terms on source ASN for `Invoke*` (data events + ASN enrichment) | Medium |
| [AWS Lambda Function Invoked Cross-Account](https://www.elastic.co/guide/en/security/current/aws-lambda-function-invoked-cross-account.html) | Elastic | T1648 | ES\|QL comparing the caller account with the function owner account (data events) | Harder |

Related rules not tagged T1648:
- [AWS IAM Sensitive Operations via Lambda Execution Role](https://www.elastic.co/guide/en/security/current/aws-iam-sensitive-operations-via-lambda-execution-role.html) (Elastic, T1078.004/T1098) finds IAM writes made *from* a Lambda role. This is the PassRole-to-Lambda abuse MITRE describes for T1648. Easy port.
- SigmaHQ [New AWS Lambda Function URL Configuration Created](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_lambda_function_url/) (`CreateFunctionUrlConfig`) and [AWS New Lambda Layer Attached](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_new_lambda_layer_attached/) are tagged with tactic only, no technique. Easy port.

## T1525 Implant Internal Image

| Rule | Source | Tags | Logic | Port |
|---|---|---|---|---|
| [New Private Repository Container Image detected in AWS ECR](https://docs.datadoghq.com/security/default_rules/aws-ecr-new-private-image/) | Datadog | T1525 | `ecr.amazonaws.com` `PutImage` | Easy |
| [New Public Repository Container Image detected in AWS ECR](https://docs.datadoghq.com/security/default_rules/bdv-1hj-qoq/) | Datadog | T1525 | `ecr-public.amazonaws.com` `PutImage` | Easy |
| [AWS ECS Task Definition That Queries The Credential Endpoint](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_ecs_task_definition_cred_endpoint_query/) | SigmaHQ | T1525 | ECS `RegisterTaskDefinition`/`RunTask`/`DescribeTaskDefinition` where the container command contains `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` | Easy |

These Datadog rules use the same `PutImage` event as Splunk's ECR rules from the first list, but Datadog maps them to T1525. Pair them with Splunk's "unknown user" or "outside business hours" filters for tuning.

Related rules not tagged T1525: [AWS EC2 AMI Shared with Another Account](https://www.elastic.co/guide/en/security/current/aws-ec2-ami-shared-with-another-account.html) (Elastic, T1537) and [AWS AMI Made Public](https://docs.datadoghq.com/security/default_rules/93d-bf1-e17) (Datadog, T1530). Both watch `ModifyImageAttribute` and are useful for the AMI side of image tampering. Easy port.

## T1546 Event Triggered Execution

| Rule | Source | Tags | Logic | Port |
|---|---|---|---|---|
| [AWS Lambda Event Source Mapping Creation](https://www.elastic.co/guide/en/security/current/aws-lambda-event-source-mapping-creation.html) | Elastic | T1546, T1648 | Lambda `CreateEventSourceMapping*`, success (wires SQS/Kinesis/DynamoDB events to a function) | Easy |
| [AWS Lambda Function Policy Updated to Allow Public Invocation](https://www.elastic.co/guide/en/security/current/aws-lambda-function-policy-updated-to-allow-public-invocation.html) | Elastic | T1546, T1578.005 | `AddPermission*` granting `lambda:InvokeFunction` to principal `*` | Easy |
| [AWS Lambda Function Policy Updated to Allow Cross-Account Invocation](https://www.elastic.co/guide/en/security/current/aws-lambda-function-policy-updated-to-allow-cross-account-invocation.html) | Elastic | T1546, T1578.005 | `AddPermission*` with `lambda:InvokeFunction`, principal not `*` and not an AWS service | Easy |

Panther's [AWS Potential Backdoor Lambda Function Through Resource-Based Policy](https://rulehound.com/rules/530769) uses the same `AddPermission` logic, tagged T1078.

**Remaining gap:** I found nothing public, in any language, for S3 bucket notifications (`PutBucketNotificationConfiguration`) or EventBridge `PutRule`/`PutTargets` pointing at a Lambda. That is the exact Pacu pattern MITRE cites for T1546.

## T1556.007 Hybrid Identity

None of the rules I found are tagged .007. The closest are federation-trust rules tagged T1556 or T1484.002 (Domain or Tenant Policy Modification: Trust Modification):

| Rule | Source | Tags | Logic | Port |
|---|---|---|---|---|
| [AWS Identity Center Identity Provider Change](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_sso_idp_change/) | SigmaHQ | T1556 | `sso`/`sso-directory` `Enable/DisableExternalIdPConfigurationForDirectory`, `Associate/DisassociateDirectory` | Easy |
| [AWS IAM Identity Center SSO configuration updated](https://docs.datadoghq.com/security/default_rules/cloudtrail-aws-sso-update-configuration/) | Datadog | T1556 | `UpdateSsoConfiguration` | Easy |
| [AWS IAM SAML Provider Updated](https://www.elastic.co/guide/en/security/current/aws-iam-saml-provider-updated.html) | Elastic | T1484.002 | `UpdateSAMLProvider`, success, excluding AWS SSO | Easy |
| [AWS IAM SAML Provider Created](https://www.elastic.co/guide/en/security/current/aws-iam-saml-provider-created.html) | Elastic | T1484.002, T1098.001 | `CreateSAMLProvider`, success | Easy |
| [AWS Suspicious SAML Activity](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_susp_saml_activity/) | SigmaHQ | T1548, T1550.001 | `AssumeRoleWithSAML` or `UpdateSAMLProvider` (noisy on `AssumeRoleWithSAML`) | Easy |
| [AWS SAML Activity](https://rulehound.com/rules/469082) | Panther | untagged | Create, Delete or Update SAML provider | Easy |

My judgement: if your AWS estate federates from Entra ID or AD FS, the stronger T1556.007 signal is on the IdP side (Entra and AD FS logs), not in CloudTrail.

## T1556.009 Conditional Access Policies

**No public rule in any source I checked is tagged T1556.009 for AWS.** The nearest proxies watch IAM policy changes that could loosen a `Condition` block, but none of them parse the condition itself:
- [AWS IAM Customer Managed Policy Version Created or Default Version Set](https://www.elastic.co/guide/en/security/current/aws-iam-customer-managed-policy-version-created-or-default-version-set.html) (Elastic, T1548.005). Easy.
- [AWS IAM Permissions Boundary Modified or Removed](https://www.elastic.co/guide/en/security/current/aws-iam-permissions-boundary-modified-or-removed.html) (Elastic, T1098). `Put/Delete{User,Role}PermissionsBoundary`. Easy.

## T1548 Abuse Elevation Control Mechanism and T1548.005 Temporary Elevated Cloud Access

| Rule | Source | Tags | Logic | Port |
|---|---|---|---|---|
| [AWS STS AssumeRoot by Rare User and Member Account](https://www.elastic.co/guide/en/security/current/aws-sts-assumeroot-by-rare-user-and-member-account.html) | Elastic | T1548.005, T1098.003 | new_terms on `sts` `AssumeRoot` | Medium |
| [AWS STS Role Assumption by Service](https://www.elastic.co/guide/en/security/current/aws-sts-role-assumption-by-service.html) | Elastic | T1548.005, T1550.001 | new_terms on `AssumeRole` by an AWS service identity | Medium |
| [AWS STS GetFederationToken with AdministratorAccess in Request](https://www.elastic.co/guide/en/security/current/aws-sts-getfederationtoken-with-administratoraccess-in-request.html) | Elastic | T1548.005, T1550.001 | `GetFederationToken` whose request parameters contain `AdministratorAccess` | Easy |
| [AWS IAM Customer Managed Policy Version Created or Default Version Set](https://www.elastic.co/guide/en/security/current/aws-iam-customer-managed-policy-version-created-or-default-version-set.html) | Elastic | T1548.005, T1098 | `CreatePolicyVersion` / `SetDefaultPolicyVersion` | Easy |
| [AWS STS Role Assumption by User](https://www.elastic.co/guide/en/security/current/aws-sts-role-assumption-by-user.html) | Elastic | T1548, T1550.001 | new_terms on `AssumeRole` by an `IAMUser` | Medium |
| [AWS STS Role Chaining](https://www.elastic.co/guide/en/security/current/aws-sts-role-chaining.html) | Elastic | T1548, T1550.001 | new_terms on `AssumeRole` where the caller is already an `AssumedRole` | Medium |
| [AWS STS AssumeRole with New MFA Device](https://www.elastic.co/guide/en/security/current/aws-sts-assumerole-with-new-mfa-device.html) | Elastic | T1548, T1556.006 | new_terms on the MFA serial in STS calls | Medium |
| [AWS STS AssumeRole Misuse](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_sts_assumerole_misuse/) | SigmaHQ | T1548, T1550.001 | `userIdentity.type=AssumedRole` with a `Role` session issuer (very noisy) | Easy |
| [AWS STS GetSessionToken Misuse](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_sts_getsessiontoken_misuse/) | SigmaHQ | T1548, T1550.001 | `GetSessionToken` by an `IAMUser` | Easy |

Related rules not tagged T1548 that cover the PassRole half of .005:
- [AWS SageMaker Execution Role Passed by Unusual Principal](https://www.elastic.co/guide/en/security/current/aws-sagemaker-execution-role-passed-by-unusual-principal.html) (Elastic, T1078.004, ES|QL). Harder.
- [AWS Bedrock AgentCore Resource Created with IAM Execution Role](https://www.elastic.co/guide/en/security/current/aws-bedrock-agentcore-resource-created-with-iam-execution-role.html) (Elastic, T1078.004). Easy.
- SigmaHQ [AWS Glue Development Endpoint Activity](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_passed_role_to_glue_development_endpoint/) (tactic tag only). Easy.
- [AWS IAM Assume Role Policy Update](https://www.elastic.co/guide/en/security/current/aws-iam-assume-role-policy-update.html) (Elastic, T1098.003). Medium.

## Microsoft Sentinel (KQL)

Microsoft's [AWS CloudTrail solution announcement](https://thewindowsupdate.com/2022/10/07/announcing-the-enhanced-microsoft-sentinel-aws-cloudtrail-solution-powered-by-new-mitre-based-rules/) lists relevant analytics. The announcement doesn't give per-rule technique IDs and I didn't confirm them, so treat this as a pointer only:
- "Privilege escalation via Lambda policy assigned to User-Group-Role"
- "Suspicious UpdateSAMLProvider event"
- Hunting queries: "Suspicious lambda layer imported from external account", "Suspicious lambda UpdateFunctionCode event", "Suspicious activity of STS token related to Lambda"

The source is the `Solutions/Amazon Web Services/Analytic Rules` folder in the Azure-Sentinel GitHub repo, for example [AWS_CreatedLambdaPolicytoPrivilegeEscalation.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Amazon%20Web%20Services/Analytic%20Rules/AWS_CreatedLambdaPolicytoPrivilegeEscalation.yaml).

## VPC Flow Logs

Still nothing for these techniques in Elastic, Sigma, Datadog, Panther or Sentinel. The only flow-log-adjacent rules are about *deleting* flow logs: [AWS VPC Flow Logs Deletion](https://www.elastic.co/guide/en/security/current/aws-vpc-flow-logs-deletion.html) (Elastic) and SigmaHQ [AWS VPC Flow Logs Deleted](https://detection.fyi/sigmahq/sigma/cloud/aws/cloudtrail/aws_cloudtrail_vpc_flow_logs_deleted/). Both are defence-evasion rules that run on CloudTrail, not on flow logs.
