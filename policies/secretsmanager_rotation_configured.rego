package compliance_framework.secretsmanager_rotation_configured

# METADATA
# title: Secrets Manager secret has rotation enabled
# description: Checks whether a customer-owned secret has automatic rotation configured.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_ROTATION
#   controls:
#     - ctrl-cc5-1-006
#     - ctrl-cc6-2-014
#     - ctrl-cc6-2-018
#     - ctrl-cc6-2-020

risk_templates := [{
	"name": "Secrets Manager secret rotation control is ineffective",
	"title": "Static Credentials Expand the Blast Radius of Credential Leakage",
	"statement": "A secret without effective rotation can retain exposed credential material beyond its intended lifetime.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-798", "title": "Use of Hard-coded Credentials", "url": "https://cwe.mitre.org/data/definitions/798.html"}],
	"remediation": {"title": "Restore secret rotation", "description": "Enable and verify automatic secret rotation within the applicable cadence.", "tasks": [{"title": "Configure automatic rotation"}, {"title": "Verify the latest rotation completed"}]},
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

skip_reason := sprintf("Secret %s is service-linked (owning_service=%q); rotation is AWS-managed.", [secret_arn, owning_service]) if {
	resource_type == "secret"
	is_service_linked
}

rotation_enabled := object.get(config, "rotation_enabled", false)
title := sprintf("Validate rotation configuration for %s", [secret_arn])
description := sprintf("Secret %s has rotation_enabled=%v.", [secret_arn, rotation_enabled])

violation[{"id": "rotation_disabled"}] if {
	resource_type == "secret"
	not is_service_linked
	not rotation_enabled
}
