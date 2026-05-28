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
	"name": "Secrets Manager resource policy grants excessive access",
	"title": "Broad Resource Policies Can Expose Secret Values or Administration",
	"statement": "Wildcard, undocumented, or over-privileged principals in a secret resource policy can grant access outside the intended trust boundary.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-732", "title": "Incorrect Permission Assignment for Critical Resource", "url": "https://cwe.mitre.org/data/definitions/732.html"}],
	"remediation": {"title": "Constrain the resource policy", "description": "Replace wildcard principals, reduce actions, and document required partner access.", "tasks": [{"title": "Remove wildcard principals"}, {"title": "Record approved principals"}]},
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
