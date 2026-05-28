package compliance_framework.secretsmanager_admin_principal_present

# METADATA
# title: Secrets Manager resource policy identifies an administrative principal
# description: Checks present resource policies for at least one configured administrative Secrets Manager action.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_ROTATION
#   controls:
#     - ctrl-cc6-2-014
#     - ctrl-cc6-2-023

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
resource_type := object.get(resource, "type", "")
secret_arn := object.get(config, "secret_arn", object.get(resource, "arn", "unknown"))
owning_service := object.get(config, "owning_service", "")

is_service_linked if {
	owning_service != ""
}

skip_reason := sprintf("Resource type %q is not a secret; this policy only applies to secret records.", [resource_type]) if {
	resource_type != "secret"
}

skip_reason := sprintf("Secret %s is service-linked (owning_service=%q); administration is AWS-managed.", [secret_arn, owning_service]) if {
	resource_type == "secret"
	is_service_linked
}

principals := object.get(object.get(config, "resource_policy", {}), "principals", [])

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

resource_policy_present := object.get(config, "resource_policy_present", false)
admin_actions_normalized := {upper(a) | a := data.admin_action_set[_]}

admin_principal_present if {
	principal := principals[_]
	allow_effect(principal)
	actions := action_list(principal)
	action := actions[_]
	admin_actions_normalized[upper(action)]
}

title := sprintf("Validate administrative principal for %s", [secret_arn])
description := sprintf("Secret %s resource_policy_present=%v.", [secret_arn, resource_policy_present])

violation[{"id": "admin_principal_missing"}] if {
	resource_type == "secret"
	not is_service_linked
	resource_policy_present
	not admin_principal_present
}
