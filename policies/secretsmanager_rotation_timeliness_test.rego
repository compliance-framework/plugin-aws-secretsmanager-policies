package compliance_framework.secretsmanager_rotation_timeliness_test

import data.compliance_framework.secretsmanager_rotation_timeliness as policy

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

test_pass if count(policy.violation) == 0 with input as base_secret with time.now_ns as 1778803200000000000

test_never_fails if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/last_rotated_date", "value": ""}])
	policy.violation[{"id": "rotation_never_executed"}] with input as inp
}

test_overdue_fails if policy.violation[{"id": "rotation_overdue"}] with input as base_secret with time.now_ns as 1782864000000000000

test_disabled_skipped if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/rotation_enabled", "value": false}])
	count(policy.violation) == 0 with input as inp with time.now_ns as 1782864000000000000
}

test_non_secret_record_skipped if {
	count(policy.violation) == 0 with input as {"resource": {"type": "loadbalancer"}}
}
