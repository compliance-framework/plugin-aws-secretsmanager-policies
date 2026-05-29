package compliance_framework.secretsmanager_replication_in_sync_test

import data.compliance_framework.secretsmanager_replication_in_sync as policy

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

test_failed_fails if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/replication_status/0/status", "value": "Failed"}])
	policy.violation[{"id": "replication_failed"}] with input as inp
}

test_unknown_skips if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/replication_status/0/status", "value": "PausedByAWS"}])
	count(policy.violation) == 0 with input as inp
	policy.skip_reason with input as inp
}

test_failed_replica_not_masked_by_unknown_status if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/replication_status", "value": [{"region": "us-west-2", "status": "Failed"}, {"region": "eu-west-1", "status": "PausedByAWS"}]}])
	policy.violation[{"id": "replication_failed"}] with input as inp
	policy.skip_reason with input as inp
}

test_non_secret_record_skipped if {
	count(policy.violation) == 0 with input as {"resource": {"type": "loadbalancer"}}
}
