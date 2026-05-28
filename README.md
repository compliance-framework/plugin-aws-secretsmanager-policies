# AWS Secrets Manager policy bundle

Standalone OPA/Rego bundle for evidence emitted by the `aws-secretsmanager` CCF plugin. The bundle evaluates `secret` records only and emits compliance violations for SOC 2 CC5, CC6, CC7, CC9, C1, and P controls.

## Input schema

Policies consume documents with no `policy_inputs` field. Tunables are flattened `data.*` values from `policies/data.json` and may be overridden by the agent `policy_data` block.

```json
{
  "schema_version": "v1",
  "source": "aws-secretsmanager",
  "account": { "account_id": "123456789012", "tags": {"environment": "prod"} },
  "region": { "name": "us-east-1" },
  "resource": {
    "id": "MyApp/db/credentials-AbCdEf",
    "arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:MyApp/db/credentials-AbCdEf",
    "type": "secret"
  },
  "config": {
    "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:MyApp/db/credentials-AbCdEf",
    "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/...",
    "rotation_enabled": true,
    "rotation_lambda_arn": "arn:aws:lambda:us-east-1:...:function:rotate-db",
    "rotation_rules": {"automatically_after_days": 30, "schedule_expression": "", "duration": ""},
    "last_rotated_date": "2026-04-12T03:00:00Z",
    "last_changed_date": "2026-04-12T03:00:00Z",
    "last_accessed_date": "2026-05-26T14:22:11Z",
    "deleted_date": "",
    "recovery_window_days": 0,
    "owning_service": "",
    "replication_status": [{"region": "us-west-2", "status": "InSync", "last_accessed_date": "...", "status_message": ""}],
    "resource_policy": {"hash": "sha256:...", "document": {}, "principals": []},
    "resource_policy_present": true,
    "versions": [],
    "deprecated_version_count": 0
  },
  "dynamic": {"cloudtrail_events": [], "iam_credential_removal_events": []},
  "tags": {"Owner": "platform-team", "DataClassification": "confidential", "IntegrationType": "vendor", "VendorId": "acme", "PrivacyScope": "pi", "DataSubjectFlow": "customer-onboarding"}
}
```

`config.kms_key_id == "aws/secretsmanager"` is the sentinel for the AWS-managed default Secrets Manager KMS key.

## Applicability

Every policy skips non-`secret` records through `skip_reason`. Vendor policies apply when `IntegrationType=vendor` or `VendorId` is present. Confidential policies apply when `DataClassification` is in `data.confidential_classification_values`. Privacy policies apply when `PrivacyScope` is in `data.privacy_scope_values`. Non-applicable tag-scoped records emit `skip_reason` rather than silent pass.

Service-linked secrets (`config.owning_service != ""`) are skipped from rotation and admin-policy checks where AWS owns those operations, but are still evaluated for KMS, replication, and applicable tag posture.

## Policies

| Applicability | Package | Controls |
| --- | --- | --- |
| Universal | `compliance_framework.secretsmanager_rotation_configured` | `ctrl-cc5-1-006`, `ctrl-cc6-2-014`, `ctrl-cc6-2-018`, `ctrl-cc6-2-020` |
| Universal | `compliance_framework.secretsmanager_kms_customer_managed` | `ctrl-cc5-1-006`, `ctrl-cc5-2-005`, `ctrl-cc6-2-014` |
| Universal | `compliance_framework.secretsmanager_resource_policy_least_privilege` | `ctrl-cc5-1-006`, `ctrl-cc6-2-014`, `ctrl-cc6-3-004`, `ctrl-cc6-2-023` |
| Universal | `compliance_framework.secretsmanager_rotation_timeliness` | `ctrl-cc6-2-019`, `ctrl-cc6-2-020` |
| Universal | `compliance_framework.secretsmanager_replication_in_sync` | `ctrl-cc5-3-033` |
| Universal | `compliance_framework.secretsmanager_scheduled_deletion_window` | `ctrl-cc6-2-018`, `ctrl-cc6-2-019` |
| Universal | `compliance_framework.secretsmanager_owner_tag_present` | `ctrl-cc6-2-023`, `ctrl-cc6-2-024` |
| Universal | `compliance_framework.secretsmanager_admin_principal_present` | `ctrl-cc6-2-014`, `ctrl-cc6-2-023` |
| Universal | `compliance_framework.secretsmanager_access_administration_events` | `ctrl-cc6-2-025`, `ctrl-cc6-2-026`, `ctrl-cc6-3-004` |
| Vendor | `compliance_framework.secretsmanager_vendor_credential_tagging` | `ctrl-cc9-2-007` |
| Vendor | `compliance_framework.secretsmanager_vendor_credential_rotation` | `ctrl-cc9-2-007` |
| Vendor | `compliance_framework.secretsmanager_vendor_credential_policy_scope` | `ctrl-cc9-2-007` |
| Confidential | `compliance_framework.secretsmanager_confidential_rotation_required` | `ctrl-c1-1-003` |
| Confidential | `compliance_framework.secretsmanager_confidential_policy_scope` | `ctrl-c1-1-003` |
| Confidential | `compliance_framework.secretsmanager_confidential_disposal_window` | `ctrl-c1-2-001`, `ctrl-c1-2-007` |
| Confidential | `compliance_framework.secretsmanager_confidential_disposal_record` | `ctrl-c1-2-006`, `ctrl-c1-2-011` |
| Privacy | `compliance_framework.secretsmanager_privacy_subprocessor_posture` | `ctrl-p6-1-004` |
| Privacy | `compliance_framework.secretsmanager_privacy_transfer_governance` | `ctrl-p6-5-002` |

## Policy data

| Key | Default | Read by | Controls |
| --- | --- | --- | --- |
| `allow_aws_managed_default_kms_for_arns` | `[]` | `secretsmanager_kms_customer_managed` | ARNs allowed to use `aws/secretsmanager`. |
| `allowed_cross_account_principals` | `[]` | `secretsmanager_resource_policy_least_privilege` | Documented cross-account principal account IDs. |
| `rotation_grace_multiplier` | `1.2` | `secretsmanager_rotation_timeliness` | Grace multiplier over configured rotation days. |
| `min_recovery_window_days` | `7` | `secretsmanager_scheduled_deletion_window` | Generic scheduled deletion minimum. |
| `allowed_force_delete_secret_arns` | `[]` | `secretsmanager_scheduled_deletion_window` | ARNs exempted from force-delete findings. |
| `required_owner_tag_keys` | `["Owner", "Team"]` | `secretsmanager_owner_tag_present` | Case-insensitive owner tag keys. |
| `admin_action_set` | `[...]` | `secretsmanager_admin_principal_present` | Actions that evidence admin principal presence. |
| `require_admin_audit_events` | `false` | `secretsmanager_access_administration_events` | Enables admin CloudTrail enforcement. |
| `admin_event_names` | `[...]` | `secretsmanager_access_administration_events` | CloudTrail event names treated as admin events. |
| `change_review_window_days` | `90` | `secretsmanager_access_administration_events` | Maximum age of newest admin event when enforcement is enabled. |
| `require_integration_type_tag` | `true` | `secretsmanager_vendor_credential_tagging` | Requires `IntegrationType` when `VendorId` exists. |
| `vendor_rotation_max_days` | `365` | `secretsmanager_vendor_credential_rotation` | Vendor credential max age. |
| `allowed_unrotated_vendor_arns` | `[]` | `secretsmanager_vendor_credential_rotation` | Vendor secret ARNs exempted from unrotated findings. |
| `allowed_vendor_actions` | `["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]` | `secretsmanager_vendor_credential_policy_scope` | Allowed vendor resource-policy actions. |
| `allowed_vendor_partner_accounts` | `[]` | `secretsmanager_vendor_credential_policy_scope` | Documented vendor partner account IDs. |
| `confidential_classification_values` | `["confidential"]` | Confidential policies | DataClassification values that enable C1 checks. |
| `max_confidential_rotation_days` | `90` | `secretsmanager_confidential_rotation_required` | Max confidential rotation cadence. |
| `cleared_principal_arns` | `[]` | `secretsmanager_confidential_policy_scope` | Optional cleared principal ARN set. Empty skips this check. |
| `min_confidential_recovery_window_days` | `30` | `secretsmanager_confidential_disposal_window` | Confidential deletion minimum. |
| `require_disposal_record` | `true` | `secretsmanager_confidential_disposal_record` | Enables disposal CloudTrail/tag evidence. |
| `privacy_scope_values` | `["pi"]` | Privacy policies | PrivacyScope values that enable P checks. |
| `pi_rotation_max_days` | `180` | `secretsmanager_privacy_subprocessor_posture` | PI credential max age. |
| `documented_integration_roles` | `{}` | `secretsmanager_privacy_subprocessor_posture` | `{vendor_id: [arn, ...]}` documented integration roles. |
| `allowed_pi_actions` | `["secretsmanager:GetSecretValue"]` | `secretsmanager_privacy_subprocessor_posture` | Allowed PI resource-policy actions. |
| `documented_data_subject_flows` | `[]` | `secretsmanager_privacy_transfer_governance` | Registered data subject flows. Empty skips register membership. |
| `account_id_to_region` | `{}` | `secretsmanager_privacy_transfer_governance` | Maps principal account IDs to processing regions. Empty skips region checks. |
| `allowed_pi_transfer_regions` | `[]` | `secretsmanager_privacy_transfer_governance` | Allowed PI transfer regions. |

## Out-of-scope P controls

The following P-family controls are intentionally excluded from infrastructure-layer evidence and should be evidenced by other collectors: `ctrl-p3-1-*` notice/consent through HR or application records, `ctrl-p4-1-*` third-party review records through customer-layer processes, `ctrl-p6-1-005` and `ctrl-p6-5-003` contractual enforcement through contract registries, and `ctrl-p6-5-001` transfer-constraint identification through application/process evidence.

## Development

```shell
opa fmt --list --fail policies
opa check --strict policies
opa test policies
make build
```

`make build` writes `dist/bundle.tar.gz`.
