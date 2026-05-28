package compliance_framework.secretsmanager_confidential_disposal_window

# METADATA
# title: Secrets Manager confidential deletion uses an approved recovery window
# description: Checks confidentiality-classified secret deletion for the stricter recovery window and no force-delete usage.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_CONFIDENTIALITY_CONTROLS
#   controls:
#     - ctrl-c1-2-001
#     - ctrl-c1-2-007

risk_templates := [{
	"name": "Secrets Manager disposal controls are incomplete",
	"title": "Secret Disposal May Bypass Retention and Authorization Evidence",
	"statement": "Deletion without an adequate recovery window or disposal record can remove confidential material without sufficient review evidence.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-1059", "title": "Insufficient Technical Documentation", "url": "https://cwe.mitre.org/data/definitions/1059.html"}],
	"remediation": {"title": "Document and control disposal", "description": "Use approved recovery windows and retain authorization evidence for secret deletion.", "tasks": [{"title": "Add disposal authorization metadata"}, {"title": "Verify DeleteSecret CloudTrail events"}]},
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

tags := object.get(input, "tags", {})
data_classification := lower(object.get(tags, "DataClassification", ""))
integration_type := lower(object.get(tags, "IntegrationType", ""))
vendor_id := object.get(tags, "VendorId", "")
privacy_scope := lower(object.get(tags, "PrivacyScope", ""))

is_vendor_secret if {
	integration_type == "vendor"
}

is_vendor_secret if {
	vendor_id != ""
}

confidential_classification_values := {lower(v) | v := data.confidential_classification_values[_]}

is_confidential if {
	confidential_classification_values[data_classification]
}

privacy_scope_values := {lower(v) | v := data.privacy_scope_values[_]}

is_pi_secret if {
	privacy_scope_values[privacy_scope]
}

skip_reason := sprintf("Secret %s is not confidentiality-classified; this policy applies only to configured DataClassification values.", [secret_arn]) if {
	resource_type == "secret"
	not is_confidential
}

deleted_date := object.get(config, "deleted_date", "")
recovery_window_days := object.get(config, "recovery_window_days", null)
title := sprintf("Validate confidential disposal window for %s", [secret_arn])
description := sprintf("Secret %s deleted_date=%q recovery_window_days=%v.", [secret_arn, deleted_date, recovery_window_days])

violation[{"id": "recovery_window_below_confidential_minimum"}] if {
	resource_type == "secret"
	is_confidential
	deleted_date != ""
	recovery_window_days != null
	recovery_window_days < data.min_confidential_recovery_window_days
}

violation[{"id": "force_delete_used"}] if {
	resource_type == "secret"
	is_confidential
	deleted_date != ""
	recovery_window_days == 0
}
