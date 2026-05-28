package compliance_framework.secretsmanager_confidential_rotation_required

# METADATA
# title: Secrets Manager confidential secret rotation is required
# description: Checks confidentiality-classified secrets for enabled rotation and a strict rotation cadence.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_CONFIDENTIALITY_CONTROLS
#   controls:
#     - ctrl-c1-1-003

risk_templates := [{
	"name": "Secrets Manager secret rotation control is ineffective",
	"title": "Static Credentials Expand the Blast Radius of Credential Leakage",
	"statement": "A secret without effective rotation can retain exposed credential material beyond its intended lifetime.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-798", "title": "Use of Hard-coded Credentials", "url": "https://cwe.mitre.org/data/definitions/798.html"}],
	"remediation": {"title": "Restore secret rotation", "description": "Enable and verify automatic secret rotation within the applicable cadence.", "tasks": [{"title": "Configure automatic rotation"}, {"title": "Verify the latest rotation completed"}]},
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

skip_reason := sprintf("Secret %s is service-linked (owning_service=%q); rotation is AWS-managed.", [secret_arn, owning_service]) if {
	resource_type == "secret"
	is_confidential
	is_service_linked
}

rotation_enabled := object.get(config, "rotation_enabled", false)
rotation_rules := object.get(config, "rotation_rules", {})
automatically_after_days := object.get(rotation_rules, "automatically_after_days", null)
schedule_expression := lower(trim_space(object.get(rotation_rules, "schedule_expression", "")))

automatically_after_days_positive if {
	automatically_after_days != null
	automatically_after_days > 0
}

schedule_rate_days := days if {
	matches := regex.find_all_string_submatch_n("^rate\\(([0-9]+) days?\\)$", schedule_expression, 1)
	count(matches) == 1
	days := to_number(matches[0][1])
	days > 0
}

schedule_rate_days_positive if {
	schedule_rate_days > 0
}

effective_rotation_days := automatically_after_days if {
	automatically_after_days_positive
}

effective_rotation_days := schedule_rate_days if {
	not automatically_after_days_positive
	schedule_rate_days_positive
}

skip_reason := sprintf("Secret %s has unsupported rotation schedule_expression=%q; collector must provide a normalized day cadence.", [secret_arn, schedule_expression]) if {
	resource_type == "secret"
	is_confidential
	not is_service_linked
	rotation_enabled
	schedule_expression != ""
	not automatically_after_days_positive
	not schedule_rate_days_positive
}

title := sprintf("Validate confidential rotation requirements for %s", [secret_arn])
description := sprintf("Secret %s rotation_enabled=%v automatically_after_days=%v.", [secret_arn, rotation_enabled, automatically_after_days])

violation[{"id": "rotation_disabled"}] if {
	resource_type == "secret"
	is_confidential
	not is_service_linked
	not rotation_enabled
}

violation[{"id": "rotation_cadence_too_long"}] if {
	resource_type == "secret"
	is_confidential
	not is_service_linked
	rotation_enabled
	effective_rotation_days > data.max_confidential_rotation_days
}
