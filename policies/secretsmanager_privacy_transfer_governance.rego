package compliance_framework.secretsmanager_privacy_transfer_governance

# METADATA
# title: Secrets Manager PI transfer governance is documented
# description: Checks privacy-scoped secrets for data-subject flow registration and approved transfer regions.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_PRIVACY_INTEGRATIONS
#   controls:
#     - ctrl-p6-5-002

risk_templates := [{
	"name": "Secrets Manager privacy transfer governance is incomplete",
	"title": "PI Secret Access May Bypass Transfer Governance",
	"statement": "Missing data-subject flow registration or undocumented cross-border principals can expose private information outside approved processing regions.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-359", "title": "Exposure of Private Personal Information", "url": "https://cwe.mitre.org/data/definitions/359.html"}],
	"remediation": {"title": "Document privacy transfer posture", "description": "Register data-subject flows and map partner accounts to approved processing regions.", "tasks": [{"title": "Register the data-subject flow"}, {"title": "Approve or remove cross-border principals"}]},
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
data_subject_flow := object.get(tags, "DataSubjectFlow", "")
documented_data_subject_flows := {flow | flow := data.documented_data_subject_flows[_]}
allowed_pi_transfer_regions := {region | region := data.allowed_pi_transfer_regions[_]}

principal_regions(principal_entry) := regions if {
	allow_effect(principal_entry)
	regions := {region |
		arn := principal_values(principal_entry)[_]
		principal_account := principal_account_id_from_value(arn)
		region := object.get(data.account_id_to_region, principal_account, "")
		region != ""
	}
}

title := sprintf("Validate PI transfer governance for %s", [secret_arn])
description := sprintf("Secret %s DataSubjectFlow=%q.", [secret_arn, data_subject_flow])

violation[{"id": "data_subject_flow_tag_missing"}] if {
	resource_type == "secret"
	is_pi_secret
	data_subject_flow == ""
}

violation[{"id": "data_subject_flow_not_in_register"}] if {
	resource_type == "secret"
	is_pi_secret
	data_subject_flow != ""
	count(data.documented_data_subject_flows) > 0
	not documented_data_subject_flows[data_subject_flow]
}

violation[{"id": "cross_border_principal_undocumented"}] if {
	resource_type == "secret"
	is_pi_secret
	resource_policy_present
	count(data.account_id_to_region) > 0
	principal := principals[_]
	region := principal_regions(principal)[_]
	not allowed_pi_transfer_regions[region]
}

violation[{"id": "cross_border_principal_undocumented"}] if {
	resource_type == "secret"
	is_pi_secret
	resource_policy_present
	count(data.account_id_to_region) > 0
	principal := principals[_]
	allow_effect(principal)
	account_id != ""
	arn := principal_values(principal)[_]
	principal_account := principal_account_id_from_value(arn)
	principal_account != account_id
	object.get(data.account_id_to_region, principal_account, "") == ""
}
