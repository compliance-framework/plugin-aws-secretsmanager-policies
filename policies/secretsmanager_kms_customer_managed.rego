package compliance_framework.secretsmanager_kms_customer_managed

# METADATA
# title: Secrets Manager secret uses a customer-managed KMS key
# description: Checks whether the secret avoids the AWS-managed aws/secretsmanager default key unless explicitly allowed.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_ROTATION
#   controls:
#     - ctrl-cc5-1-006
#     - ctrl-cc5-2-005
#     - ctrl-cc6-2-014

risk_templates := [{
	"name": "Secrets Manager secret uses AWS-managed default encryption",
	"title": "Default Key Management Weakens Customer Control Over Secret Encryption",
	"statement": "Secrets encrypted with the AWS-managed default key cannot enforce customer-managed key policy, rotation, and audit boundaries.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-321", "title": "Use of Hard-coded Cryptographic Key", "url": "https://cwe.mitre.org/data/definitions/321.html"}],
	"remediation": {"title": "Use a customer-managed KMS key", "description": "Re-encrypt the secret with an approved customer-managed KMS key unless a documented exception applies.", "tasks": [{"title": "Select an approved CMK"}, {"title": "Update the secret KMS key"}]},
}]

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
account := object.get(input, "account", {})
resource_type := object.get(resource, "type", "")
secret_arn := object.get(config, "secret_arn", object.get(resource, "arn", "unknown"))
owning_service := object.get(config, "owning_service", "")

is_service_linked if {
	owning_service != ""
}

skip_reason := sprintf("Resource type %q is not a secret; this policy only applies to secret records.", [resource_type]) if {
	resource_type != "secret"
}

kms_key_id := object.get(config, "kms_key_id", "")
allowed_aws_managed_default_kms_arns := {arn | arn := data.allow_aws_managed_default_kms_for_arns[_]}
allowed_aws_managed_default_kms if allowed_aws_managed_default_kms_arns[secret_arn]
title := sprintf("Validate KMS key selection for %s", [secret_arn])
description := sprintf("Secret %s uses kms_key_id=%q.", [secret_arn, kms_key_id])

violation[{"id": "aws_managed_default_kms_key"}] if {
	resource_type == "secret"
	kms_key_id == "aws/secretsmanager"
	not allowed_aws_managed_default_kms
}
