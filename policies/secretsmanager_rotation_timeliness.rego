package compliance_framework.secretsmanager_rotation_timeliness

# METADATA
# title: Secrets Manager secret rotation is timely
# description: Checks whether enabled rotation has executed within the configured cadence plus grace multiplier.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_ROTATION
#   controls:
#     - ctrl-cc6-2-019
#     - ctrl-cc6-2-020

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

is_service_linked if {
	owning_service != ""
}

skip_reason := sprintf("Resource type %q is not a secret; this policy only applies to secret records.", [resource_type]) if {
	resource_type != "secret"
}

skip_reason := sprintf("Secret %s does not have rotation enabled; rotation configuration is covered by secretsmanager_rotation_configured.", [secret_arn]) if {
	resource_type == "secret"
	not rotation_enabled
}

rotation_enabled := object.get(config, "rotation_enabled", false)
last_rotated_date := object.get(config, "last_rotated_date", "")
rotation_rules := object.get(config, "rotation_rules", {})
automatically_after_days := object.get(rotation_rules, "automatically_after_days", null)

now_ns := time.now_ns()

days_since_rotation := days if {
	last_rotated_date != ""
	last_rotated_ns := time.parse_rfc3339_ns(last_rotated_date)
	days := ((((now_ns - last_rotated_ns) / 1000000000) / 60) / 60) / 24
}

rotation_deadline_days := automatically_after_days * data.rotation_grace_multiplier if {
	automatically_after_days != null
	automatically_after_days > 0
}

title := sprintf("Validate rotation timeliness for %s", [secret_arn])
description := sprintf("Secret %s last_rotated_date=%q and automatically_after_days=%v.", [secret_arn, last_rotated_date, automatically_after_days])

violation[{"id": "rotation_never_executed"}] if {
	resource_type == "secret"
	rotation_enabled
	last_rotated_date == ""
}

violation[{"id": "rotation_overdue"}] if {
	resource_type == "secret"
	rotation_enabled
	last_rotated_date != ""
	automatically_after_days != null
	automatically_after_days > 0
	days_since_rotation > rotation_deadline_days
}
