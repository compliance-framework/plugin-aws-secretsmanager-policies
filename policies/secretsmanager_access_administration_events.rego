package compliance_framework.secretsmanager_access_administration_events

# METADATA
# title: Secrets Manager administration events are auditable
# description: Checks CloudTrail administration evidence when audit enforcement is enabled.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_ROTATION
#   controls:
#     - ctrl-cc6-2-025
#     - ctrl-cc6-2-026
#     - ctrl-cc6-3-004

risk_templates := [{
	"name": "Secrets Manager administration lacks audit evidence",
	"title": "Secret Administration Cannot Be Attributed or Reviewed",
	"statement": "Missing, stale, or unattributed CloudTrail events reduce the ability to verify administrative changes to sensitive secrets.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-778", "title": "Insufficient Logging", "url": "https://cwe.mitre.org/data/definitions/778.html"}],
	"remediation": {"title": "Restore audit evidence", "description": "Ensure CloudTrail captures secret administration events with attributable identities inside the review window.", "tasks": [{"title": "Validate CloudTrail delivery"}, {"title": "Review unattributed events"}]},
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

dynamic := object.get(input, "dynamic", {})
cloudtrail_events := object.get(dynamic, "cloudtrail_events", [])
admin_event_names := {name | name := data.admin_event_names[_]}
matching_admin_events := [event | event := cloudtrail_events[_]; admin_event_names[object.get(event, "event_name", "")]]
matching_admin_event_times := [time.parse_rfc3339_ns(object.get(event, "event_time", "")) | event := matching_admin_events[_]; object.get(event, "event_time", "") != ""]

now_ns := time.now_ns()
newest_admin_event_ns := max(matching_admin_event_times) if count(matching_admin_event_times) > 0
days_since_newest_admin_event := ((((now_ns - newest_admin_event_ns) / 1000000000) / 60) / 60) / 24
title := sprintf("Validate administration audit events for %s", [secret_arn])
description := sprintf("Secret %s has %v matching admin events.", [secret_arn, count(matching_admin_events)])

violation[{"id": "admin_events_missing"}] if {
	resource_type == "secret"
	data.require_admin_audit_events
	count(matching_admin_events) == 0
}

violation[{"id": "admin_event_unattributable"}] if {
	resource_type == "secret"
	data.require_admin_audit_events
	event := matching_admin_events[_]
	object.get(event, "user_identity_arn", "") == ""
}

violation[{"id": "admin_event_missing_timestamp"}] if {
	resource_type == "secret"
	data.require_admin_audit_events
	count(matching_admin_events) > 0
	count(matching_admin_event_times) == 0
}

violation[{"id": "admin_event_stale"}] if {
	resource_type == "secret"
	data.require_admin_audit_events
	count(matching_admin_events) > 0
	days_since_newest_admin_event > data.change_review_window_days
}
