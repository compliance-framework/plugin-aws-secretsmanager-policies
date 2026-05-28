package compliance_framework.secretsmanager_confidential_policy_scope

# METADATA
# title: Secrets Manager confidential resource policy is same-account and cleared
# description: Checks confidentiality-classified resource policies for wildcard, cross-account, and uncleared principals.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_CONFIDENTIALITY_CONTROLS
#   controls:
#     - ctrl-c1-1-003

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

skip_reason := sprintf("Secret %s is not confidentiality-classified; this policy applies only to configured DataClassification values.", [secret_arn]) if {
	resource_type == "secret"
	not is_confidential
}

principals := object.get(object.get(config, "resource_policy", {}), "principals", [])
account_id := object.get(account, "account_id", "")

principal_values(principal_entry) := values if {
	values := ({v |
		principal := object.get(principal_entry, "principal", "")
		is_string(principal)
		v := principal
	} | {v |
		principal := object.get(principal_entry, "principal", {})
		is_object(principal)
		aws := object.get(principal, "AWS", "")
		is_string(aws)
		v := aws
	}) | {v |
		principal := object.get(principal_entry, "principal", {})
		is_object(principal)
		aws := object.get(principal, "AWS", [])
		is_array(aws)
		v := aws[_]
		is_string(v)
	}
}

principal_is_wildcard(principal_entry) if {
	principal_values(principal_entry)["*"]
}

allow_effect(principal_entry) if {
	lower(object.get(principal_entry, "effect", "")) == "allow"
}

principal_account_id_from_value(arn) := principal_account if {
	regex.match("^[0-9]{12}$", arn)
	principal_account = arn
}

principal_account_id_from_value(arn) := principal_account if {
	parts := split(arn, ":")
	count(parts) > 4
	principal_account = parts[4]
	regex.match("^[0-9]{12}$", principal_account)
}

resource_policy_present := object.get(config, "resource_policy_present", false)
cleared_principal_arns := {arn | arn := data.cleared_principal_arns[_]}
title := sprintf("Validate confidential policy scope for %s", [secret_arn])
description := sprintf("Secret %s resource_policy_present=%v.", [secret_arn, resource_policy_present])

violation[{"id": "wildcard_principal"}] if {
	resource_type == "secret"
	is_confidential
	resource_policy_present
	principal := principals[_]
	allow_effect(principal)
	principal_is_wildcard(principal)
}

violation[{"id": "cross_account_principal"}] if {
	resource_type == "secret"
	is_confidential
	resource_policy_present
	principal := principals[_]
	allow_effect(principal)
	account_id != ""
	arn := principal_values(principal)[_]
	principal_account := principal_account_id_from_value(arn)
	principal_account != account_id
}

violation[{"id": "principal_outside_cleared_role_set"}] if {
	resource_type == "secret"
	is_confidential
	resource_policy_present
	count(data.cleared_principal_arns) > 0
	principal := principals[_]
	allow_effect(principal)
	not principal_is_wildcard(principal)
	arn := principal_values(principal)[_]
	not cleared_principal_arns[arn]
}
