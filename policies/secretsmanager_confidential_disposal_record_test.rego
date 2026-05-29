package compliance_framework.secretsmanager_confidential_disposal_record_test

import data.compliance_framework.secretsmanager_confidential_disposal_record as policy

base_secret := {
	"schema_version": "v1",
	"source": "aws-secretsmanager",
	"account": {"account_id": "123456789012"},
	"region": {"name": "us-east-1"},
	"resource": {
		"id": "s-1",
		"arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:s-1",
		"type": "secret",
	},
	"config": {
		"secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:s-1",
		"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/1",
		"rotation_enabled": true,
		"rotation_rules": {"automatically_after_days": 30},
		"last_rotated_date": "2026-05-01T00:00:00Z",
		"deleted_date": "",
		"recovery_window_days": 30,
		"owning_service": "",
		"resource_policy_present": true,
		"resource_policy": {"principals": [{
			"principal": "arn:aws:iam::123456789012:role/admin",
			"action": ["secretsmanager:*"],
			"effect": "Allow",
			"condition": null,
		}]},
		"replication_status": [{
			"region": "us-west-2",
			"status": "InSync",
		}],
	},
	"dynamic": {"cloudtrail_events": [{
		"event_name": "RotateSecret",
		"event_time": "2026-05-01T00:00:00Z",
		"user_identity_arn": "arn:aws:iam::123456789012:role/admin",
	}]},
	"tags": {
		"Owner": "platform",
		"DataClassification": "confidential",
		"IntegrationType": "vendor",
		"VendorId": "acme",
		"PrivacyScope": "pi",
		"DataSubjectFlow": "customer-onboarding",
		"DisposalAuthorisation": "ticket-1",
	},
}

test_pass if count(policy.violation) == 0 with input as base_secret

test_unrecorded if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/deleted_date", "value": "2026-05-20T00:00:00Z"}])
	policy.violation[{"id": "unrecorded_administration"}] with input as inp
}

test_missing_authorisation if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/dynamic/cloudtrail_events", "value": [{"event_name": "DeleteSecret", "event_time": "2026-05-20T00:00:00Z", "user_identity_arn": "arn:aws:iam::123456789012:role/admin", "secret_arn": base_secret.config.secret_arn}]}, {"op": "replace", "path": "/tags/DisposalAuthorisation", "value": ""}])
	policy.violation[{"id": "disposal_authorisation_tag_missing"}] with input as inp
}

test_unattributable if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/dynamic/cloudtrail_events", "value": [{"event_name": "DeleteSecret", "event_time": "2026-05-20T00:00:00Z", "user_identity_arn": "", "requestParameters": {"secretId": base_secret.config.secret_arn}}]}])
	policy.violation[{"id": "disposal_event_unattributable"}] with input as inp
}

test_delete_secret_events_scoped_to_secret if {
	events := [
		{"event_name": "DeleteSecret", "event_time": "2026-05-20T00:00:00Z", "user_identity_arn": "", "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:other"},
		{"event_name": "DeleteSecret", "event_time": "2026-05-21T00:00:00Z", "user_identity_arn": "arn:aws:iam::123456789012:role/admin", "resources": [{"ARN": base_secret.config.secret_arn}]},
	]
	inp := json.patch(base_secret, [{"op": "replace", "path": "/dynamic/cloudtrail_events", "value": events}, {"op": "replace", "path": "/tags/DisposalAuthorisation", "value": ""}])
	policy.violation[{"id": "disposal_authorisation_tag_missing"}] with input as inp
	not policy.violation[{"id": "disposal_event_unattributable"}] with input as inp
}

test_delete_secret_event_with_short_secret_id_and_resource_arn_matches if {
	event := {"event_name": "DeleteSecret", "event_time": "2026-05-20T00:00:00Z", "user_identity_arn": "arn:aws:iam::123456789012:role/admin", "requestParameters": {"secretId": "s-1"}, "resources": [{"ARN": base_secret.config.secret_arn}]}
	inp := json.patch(base_secret, [{"op": "replace", "path": "/dynamic/cloudtrail_events", "value": [event]}, {"op": "replace", "path": "/tags/DisposalAuthorisation", "value": ""}])
	policy.violation[{"id": "disposal_authorisation_tag_missing"}] with input as inp
	not policy.violation[{"id": "disposal_event_unattributable"}] with input as inp
}

test_disabled_requirement if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/deleted_date", "value": "2026-05-20T00:00:00Z"}])
	count(policy.violation) == 0 with input as inp with data.require_disposal_record as false
}
