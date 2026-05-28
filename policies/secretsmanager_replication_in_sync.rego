package compliance_framework.secretsmanager_replication_in_sync

# METADATA
# title: Secrets Manager replication status is healthy
# description: Checks replica regions for failed replication states while skipping unknown future statuses.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_ROTATION
#   controls:
#     - ctrl-cc5-3-033

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

recognized_replication_states := {"InSync", "InProgress", "Failed"}
replication_status := object.get(config, "replication_status", [])
unrecognized_replication_statuses := {status | entry := replication_status[_]; status := object.get(entry, "status", ""); status != ""; not recognized_replication_states[status]}

skip_reason := sprintf("Secret %s has unrecognized replication status values %v; unknown statuses are skipped for forward compatibility.", [secret_arn, unrecognized_replication_statuses]) if {
	resource_type == "secret"
	count(unrecognized_replication_statuses) > 0
}

title := sprintf("Validate replication status for %s", [secret_arn])
description := sprintf("Secret %s replication_status entries are evaluated for Failed states.", [secret_arn])

violation[{"id": "replication_failed"}] if {
	resource_type == "secret"
	entry := replication_status[_]
	object.get(entry, "status", "") == "Failed"
}
