package compliance_framework.secretsmanager_vendor_credential_rotation

import data.ccf_libs.secretsmanager_common

# METADATA
# title: Secrets Manager vendor credential rotation is current
# description: Checks vendor-scoped secrets against the contractual vendor rotation cadence.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_VENDOR_CREDENTIALS
#   controls:
#     - ctrl-cc9-2-007

risk_templates := [{
	"name": "Secrets Manager secret rotation is stale",
	"title": "Expired Credential Material Remains Active",
	"statement": "A secret that is not rotated within its required interval can leave expired or exposed credentials usable in production.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-672", "title": "Operation on a Resource after Expiration or Release", "url": "https://cwe.mitre.org/data/definitions/672.html"}],
	"remediation": {"title": "Rotate stale secret material", "description": "Run or repair automatic rotation and confirm the newest rotation is inside the approved window.", "tasks": [{"title": "Investigate failed rotations"}, {"title": "Trigger and verify rotation"}]},
}]

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
account := object.get(input, "account", {})
resource_type := object.get(resource, "type", "")
secret_arn := object.get(config, "secret_arn", object.get(resource, "arn", "unknown"))
owning_service := object.get(config, "owning_service", "")
pending_deletion if secretsmanager_common.pending_deletion(input)

is_service_linked if {
	owning_service != ""
}

skip_reason := sprintf("Resource type %q is not a secret; this policy only applies to secret records.", [resource_type]) if {
	resource_type != "secret"
}

skip_reason := secretsmanager_common.pending_deletion_skip_reason(input) if {
	resource_type == "secret"
	pending_deletion
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

confidential_classification_values := {lower(v) | v := data.confidential_classification_values[_]} # regal ignore:unresolved-reference

is_confidential if {
	confidential_classification_values[data_classification]
}

privacy_scope_values := {lower(v) | v := data.privacy_scope_values[_]} # regal ignore:unresolved-reference

is_pi_secret if {
	privacy_scope_values[privacy_scope]
}

skip_reason := sprintf("Secret %s is not vendor-scoped; this policy applies only to IntegrationType=vendor or VendorId-tagged secrets.", [secret_arn]) if {
	resource_type == "secret"
	not pending_deletion
	not is_vendor_secret
}

skip_reason := sprintf("Secret %s is service-linked (owning_service=%q); rotation is AWS-managed.", [secret_arn, owning_service]) if {
	resource_type == "secret"
	not pending_deletion
	is_vendor_secret
	is_service_linked
}

rotation_enabled := object.get(config, "rotation_enabled", false)
last_rotated_date := object.get(config, "last_rotated_date", "")
allowed_unrotated_vendor_arns := {arn | arn := data.allowed_unrotated_vendor_arns[_]} # regal ignore:unresolved-reference
allowed_unrotated_vendor if allowed_unrotated_vendor_arns[secret_arn]

now_ns := time.now_ns()

days_since_rotation := days if {
	last_rotated_date != ""
	last_rotated_ns := time.parse_rfc3339_ns(last_rotated_date)
	days := ((((now_ns - last_rotated_ns) / 1000000000) / 60) / 60) / 24
}

title := sprintf("Validate vendor credential rotation for %s", [secret_arn])
description := sprintf("Secret %s last_rotated_date=%q.", [secret_arn, last_rotated_date])

violation[{"id": "vendor_rotation_never_executed"}] if {
	resource_type == "secret"
	not pending_deletion
	is_vendor_secret
	not is_service_linked
	not allowed_unrotated_vendor
	rotation_enabled
	last_rotated_date == ""
}

violation[{"id": "vendor_rotation_stale"}] if {
	resource_type == "secret"
	not pending_deletion
	is_vendor_secret
	not is_service_linked
	not allowed_unrotated_vendor
	rotation_enabled
	last_rotated_date != ""
	days_since_rotation > data.vendor_rotation_max_days # regal ignore:unresolved-reference
}
