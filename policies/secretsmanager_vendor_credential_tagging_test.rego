package compliance_framework.secretsmanager_vendor_credential_tagging_test

import data.compliance_framework.secretsmanager_vendor_credential_tagging as policy

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

test_vendor_id_missing if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/tags/VendorId", "value": ""}])
	policy.violation[{"id": "vendor_id_tag_missing"}] with input as inp
}

test_integration_type_missing_if_required if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/tags/IntegrationType", "value": ""}])
	policy.violation[{"id": "integration_type_tag_missing"}] with input as inp
	count(policy.violation) == 0 with input as inp with data.require_integration_type_tag as false
}

test_non_vendor_skipped if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/tags/IntegrationType", "value": "internal"}, {"op": "replace", "path": "/tags/VendorId", "value": ""}])
	count(policy.violation) == 0 with input as inp
	policy.skip_reason with input as inp
}

test_pending_deletion_skip_takes_precedence_over_scope_skip if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/deleted_date", "value": "2026-05-20T00:00:00Z"}, {"op": "replace", "path": "/tags/IntegrationType", "value": "internal"}, {"op": "replace", "path": "/tags/VendorId", "value": ""}])
	count(policy.violation) == 0 with input as inp
	policy.skip_reason == sprintf("Secret %s is pending deletion (deleted_date=%q); steady-state posture is not evaluated for secrets scheduled for deletion.", [base_secret.config.secret_arn, "2026-05-20T00:00:00Z"]) with input as inp
}
