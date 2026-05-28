package compliance_framework.secretsmanager_privacy_subprocessor_posture

# METADATA
# title: Secrets Manager PI subprocessor posture is controlled
# description: Checks privacy-scoped integration secrets for vendor, encryption, rotation, and resource-policy posture.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_PRIVACY_INTEGRATIONS
#   controls:
#     - ctrl-p6-1-004

risk_templates := [{
	"name": "Secrets Manager principal has excessive PI access",
	"title": "Vendor Integration Access Exceeds Privacy Role Boundaries",
	"statement": "Excessive actions or undocumented principals on PI secrets can expose private information beyond approved integration paths.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-269", "title": "Improper Privilege Management", "url": "https://cwe.mitre.org/data/definitions/269.html"}],
	"remediation": {"title": "Restrict PI integration access", "description": "Limit PI secret policies to documented integration roles and minimum read actions.", "tasks": [{"title": "Document the vendor integration role"}, {"title": "Remove excessive secret actions"}]},
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

skip_reason := sprintf("Secret %s is not privacy-scoped; this policy applies only to configured PrivacyScope values.", [secret_arn]) if {
	resource_type == "secret"
	not is_pi_secret
}

principals := object.get(object.get(config, "resource_policy", {}), "principals", [])
account_id := object.get(account, "account_id", "")

principal_is_wildcard(principal_entry) if {
	principal := object.get(principal_entry, "principal", "")
	principal == "*"
}

principal_is_wildcard(principal_entry) if {
	principal := object.get(principal_entry, "principal", {})
	is_object(principal)
	object.get(principal, "AWS", "") == "*"
}

principal_arn(principal_entry) := arn if {
	principal := object.get(principal_entry, "principal", "")
	is_string(principal)
	arn := principal
}

principal_arn(principal_entry) := arn if {
	principal := object.get(principal_entry, "principal", {})
	is_object(principal)
	aws := object.get(principal, "AWS", "")
	is_string(aws)
	arn := aws
}

allow_effect(principal_entry) if {
	lower(object.get(principal_entry, "effect", "")) == "allow"
}

principal_account_id(principal_entry) := principal_account if {
	arn := principal_arn(principal_entry)
	parts := split(arn, ":")
	count(parts) > 4
	principal_account := parts[4]
	regex.match("^[0-9]{12}$", principal_account)
}

kms_key_id := object.get(config, "kms_key_id", "")
rotation_enabled := object.get(config, "rotation_enabled", false)
last_rotated_date := object.get(config, "last_rotated_date", "")
resource_policy_present := object.get(config, "resource_policy_present", false)
documented_roles_for_vendor := object.get(data.documented_integration_roles, vendor_id, [])
documented_roles_for_vendor_set := {arn | arn := documented_roles_for_vendor[_]}
allowed_pi_actions_normalized := {upper(a) | a := data.allowed_pi_actions[_]}

vendor_documented if {
	vendor_id != ""
	object.get(data.documented_integration_roles, vendor_id, null) != null
}

now_ns := time.now_ns()

days_since_rotation := days if {
	last_rotated_date != ""
	last_rotated_ns := time.parse_rfc3339_ns(last_rotated_date)
	days := ((((now_ns - last_rotated_ns) / 1000000000) / 60) / 60) / 24
}

title := sprintf("Validate PI subprocessor posture for %s", [secret_arn])
description := sprintf("Secret %s VendorId=%q resource_policy_present=%v.", [secret_arn, vendor_id, resource_policy_present])

violation[{"id": "vendor_id_tag_missing"}] if {
	resource_type == "secret"
	is_pi_secret
	vendor_id == ""
}

violation[{"id": "aws_managed_default_kms_key"}] if {
	resource_type == "secret"
	is_pi_secret
	kms_key_id == "aws/secretsmanager"
}

violation[{"id": "rotation_disabled"}] if {
	resource_type == "secret"
	is_pi_secret
	not is_service_linked
	not rotation_enabled
}

violation[{"id": "rotation_overdue"}] if {
	resource_type == "secret"
	is_pi_secret
	not is_service_linked
	rotation_enabled
	last_rotated_date != ""
	days_since_rotation > data.pi_rotation_max_days
}

violation[{"id": "principal_wildcard"}] if {
	resource_type == "secret"
	is_pi_secret
	resource_policy_present
	principal := principals[_]
	allow_effect(principal)
	principal_is_wildcard(principal)
}

violation[{"id": "vendor_integration_role_not_documented"}] if {
	resource_type == "secret"
	is_pi_secret
	resource_policy_present
	vendor_id != ""
	not vendor_documented
}

violation[{"id": "principal_outside_integration_role_set"}] if {
	resource_type == "secret"
	is_pi_secret
	resource_policy_present
	vendor_documented
	principal := principals[_]
	allow_effect(principal)
	arn := principal_arn(principal)
	not documented_roles_for_vendor_set[arn]
}

violation[{"id": "excess_actions"}] if {
	resource_type == "secret"
	is_pi_secret
	resource_policy_present
	principal := principals[_]
	allow_effect(principal)
	actions := object.get(principal, "action", [])
	action := actions[_]
	not allowed_pi_actions_normalized[upper(action)]
}
