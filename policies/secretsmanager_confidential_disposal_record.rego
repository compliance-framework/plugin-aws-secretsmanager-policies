package compliance_framework.secretsmanager_confidential_disposal_record

# METADATA
# title: Secrets Manager confidential disposal has an audit record
# description: Checks confidential secret deletion for DeleteSecret CloudTrail evidence and disposal authorization tags.
# custom:
#   metric_ids:
#     - SECRETS_MANAGER_CONFIDENTIALITY_CONTROLS
#   controls:
#     - ctrl-c1-2-006
#     - ctrl-c1-2-011

risk_templates := [{
	"name": "Secrets Manager disposal controls are incomplete",
	"title": "Secret Disposal May Bypass Retention and Authorization Evidence",
	"statement": "Deletion without an adequate recovery window or disposal record can remove confidential material without sufficient review evidence.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-1059", "title": "Insufficient Technical Documentation", "url": "https://cwe.mitre.org/data/definitions/1059.html"}],
	"remediation": {"title": "Document and control disposal", "description": "Use approved recovery windows and retain authorization evidence for secret deletion.", "tasks": [{"title": "Add disposal authorization metadata"}, {"title": "Verify DeleteSecret CloudTrail events"}]},
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

dynamic := object.get(input, "dynamic", {})
cloudtrail_events := object.get(dynamic, "cloudtrail_events", [])
deleted_date := object.get(config, "deleted_date", "")

event_secret_ids(event) := ids if {
	ids := (({id |
		id := object.get(event, "secret_arn", "")
		id != ""
	} | {id |
		params := object.get(event, "request_parameters", {})
		id := object.get(params, "secret_arn", "")
		id != ""
	}) | ({id |
		params := object.get(event, "request_parameters", {})
		id := object.get(params, "secret_id", "")
		id != ""
	} | {id |
		params := object.get(event, "requestParameters", {})
		id := object.get(params, "secretArn", "")
		id != ""
	})) | ({id |
		params := object.get(event, "requestParameters", {})
		id := object.get(params, "secretId", "")
		id != ""
	} | {id |
		resource := object.get(event, "resources", [])[_]
		id := object.get(resource, "ARN", object.get(resource, "arn", ""))
		id != ""
	})
}

event_matches_secret(event) if {
	event_secret_ids(event)[secret_arn]
}

delete_secret_events := [event | event := cloudtrail_events[_]; object.get(event, "event_name", "") == "DeleteSecret"; event_matches_secret(event)]
disposal_authorisation := object.get(tags, "DisposalAuthorisation", "")
title := sprintf("Validate confidential disposal record for %s", [secret_arn])
description := sprintf("Secret %s has %v DeleteSecret events.", [secret_arn, count(delete_secret_events)])

violation[{"id": "disposal_authorisation_tag_missing"}] if {
	resource_type == "secret"
	is_confidential
	data.require_disposal_record
	count(delete_secret_events) > 0
	disposal_authorisation == ""
}

violation[{"id": "disposal_event_unattributable"}] if {
	resource_type == "secret"
	is_confidential
	data.require_disposal_record
	event := delete_secret_events[_]
	object.get(event, "user_identity_arn", "") == ""
}

violation[{"id": "unrecorded_administration"}] if {
	resource_type == "secret"
	is_confidential
	data.require_disposal_record
	deleted_date != ""
	count(delete_secret_events) == 0
}
