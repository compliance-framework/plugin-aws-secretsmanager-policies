package compliance_framework.secretsmanager_scheduled_deletion_window

# METADATA
# title: Secrets Manager scheduled deletion uses an approved recovery window
# description: Checks scheduled secret deletion for minimum recovery windows and force-delete exceptions.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_ROTATION
#   controls:
#     - ctrl-cc6-2-018
#     - ctrl-cc6-2-019

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

deleted_date := object.get(config, "deleted_date", "")
recovery_window_days := object.get(config, "recovery_window_days", null)
allowed_force_delete_arns := {arn | arn := data.allowed_force_delete_secret_arns[_]}
force_delete_allowed if allowed_force_delete_arns[secret_arn]
title := sprintf("Validate scheduled deletion window for %s", [secret_arn])
description := sprintf("Secret %s deleted_date=%q and recovery_window_days=%v.", [secret_arn, deleted_date, recovery_window_days])

violation[{"id": "recovery_window_below_minimum"}] if {
	resource_type == "secret"
	deleted_date != ""
	recovery_window_days != null
	recovery_window_days < data.min_recovery_window_days
}

violation[{"id": "force_delete_used"}] if {
	resource_type == "secret"
	deleted_date != ""
	recovery_window_days == 0
	not force_delete_allowed
}
