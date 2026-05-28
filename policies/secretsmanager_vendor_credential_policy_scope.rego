package compliance_framework.secretsmanager_vendor_credential_policy_scope

# METADATA
# title: Secrets Manager vendor credential policy is scoped
# description: Checks vendor-scoped resource policies for wildcard principals, excess actions, and undocumented partner accounts.
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

action_list(principal_entry) := actions if {
	raw := object.get(principal_entry, "action", [])
	is_array(raw)
	actions := raw
}

action_list(principal_entry) := [raw] if {
	raw := object.get(principal_entry, "action", "")
	is_string(raw)
	raw != ""
}

principal_account_id(principal_entry) := principal_account if {
	arn := principal_arn(principal_entry)
	regex.match(`^[0-9]{12}$`, arn)
	principal_account := arn
}

principal_account_id(principal_entry) := principal_account if {
	arn := principal_arn(principal_entry)
	parts := split(arn, ":")
	count(parts) > 4
	principal_account := parts[4]
	regex.match(`^[0-9]{12}$`, principal_account)
}

resource_policy_present := object.get(config, "resource_policy_present", false)
allowed_vendor_actions_normalized := {upper(a) | a := data.allowed_vendor_actions[_]}
allowed_vendor_partner_accounts := {id | id := data.allowed_vendor_partner_accounts[_]}
title := sprintf("Validate vendor credential policy for %s", [secret_arn])
description := sprintf("Secret %s resource_policy_present=%v.", [secret_arn, resource_policy_present])

violation[{"id": "vendor_principal_wildcard"}] if {
	resource_type == "secret"
	is_vendor_secret
	resource_policy_present
	principal := principals[_]
	allow_effect(principal)
	principal_is_wildcard(principal)
}

violation[{"id": "vendor_principal_excess_actions"}] if {
	resource_type == "secret"
	is_vendor_secret
	resource_policy_present
	principal := principals[_]
	allow_effect(principal)
	actions := action_list(principal)
	action := actions[_]
	not allowed_vendor_actions_normalized[upper(action)]
}

violation[{"id": "vendor_principal_cross_account_undocumented"}] if {
	resource_type == "secret"
	is_vendor_secret
	resource_policy_present
	principal := principals[_]
	allow_effect(principal)
	principal_account := principal_account_id(principal)
	principal_account != account_id
	not allowed_vendor_partner_accounts[principal_account]
}
