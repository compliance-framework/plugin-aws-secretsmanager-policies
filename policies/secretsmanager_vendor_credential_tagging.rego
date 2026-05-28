package compliance_framework.secretsmanager_vendor_credential_tagging

# METADATA
# title: Secrets Manager vendor credential tags are complete
# description: Checks vendor-scoped secrets for required vendor identification tags.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_VENDOR_CREDENTIALS
#   controls:
#     - ctrl-cc9-2-007

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

skip_reason := sprintf("Secret %s is not vendor-scoped; this policy applies only to IntegrationType=vendor or VendorId-tagged secrets.", [secret_arn]) if {
	resource_type == "secret"
	not is_vendor_secret
}

title := sprintf("Validate vendor credential tags for %s", [secret_arn])
description := sprintf("Secret %s VendorId=%q IntegrationType=%q.", [secret_arn, vendor_id, integration_type])

violation[{"id": "vendor_id_tag_missing"}] if {
	resource_type == "secret"
	is_vendor_secret
	vendor_id == ""
}

violation[{"id": "integration_type_tag_missing"}] if {
	resource_type == "secret"
	is_vendor_secret
	data.require_integration_type_tag
	vendor_id != ""
	integration_type == ""
}
