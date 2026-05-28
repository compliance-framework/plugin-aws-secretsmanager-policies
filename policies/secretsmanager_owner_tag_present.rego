package compliance_framework.secretsmanager_owner_tag_present

# METADATA
# title: Secrets Manager secret has an owner tag
# description: Checks that customer-owned secrets carry at least one configured owner tag key with a non-empty value.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_ROTATION
#   controls:
#     - ctrl-cc6-2-023
#     - ctrl-cc6-2-024

risk_templates := [{
	"name": "Secrets Manager secret is missing ownership tagging",
	"title": "Missing Ownership Metadata Reduces Secret Accountability",
	"statement": "Missing owner tags reduce accountability for secret review, rotation, and access decisions.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-1059", "title": "Insufficient Technical Documentation", "url": "https://cwe.mitre.org/data/definitions/1059.html"}],
	"remediation": {"title": "Restore ownership metadata", "description": "Tag the secret with a responsible owner and reconcile it with ownership records.", "tasks": [{"title": "Add an Owner or Team tag"}, {"title": "Reconcile with the resource owner registry"}]},
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

skip_reason := sprintf("Secret %s is service-linked (owning_service=%q); ownership is AWS-managed.", [secret_arn, owning_service]) if {
	resource_type == "secret"
	is_service_linked
}

required_owner_tag_keys_normalized := {lower(k) | k := data.required_owner_tag_keys[_]}

owner_tag_present if {
	some key, value in tags
	value != ""
	required_owner_tag_keys_normalized[lower(key)]
}

title := sprintf("Validate owner tag for %s", [secret_arn])
description := sprintf("Secret %s owner tag keys are checked case-insensitively.", [secret_arn])

violation[{"id": "owner_tag_missing"}] if {
	resource_type == "secret"
	not is_service_linked
	not owner_tag_present
}
