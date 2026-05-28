package compliance_framework.secretsmanager_privacy_subprocessor_posture_test

import data.compliance_framework.secretsmanager_privacy_subprocessor_posture as policy

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

test_pass if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/action", "value": ["secretsmanager:GetSecretValue"]}])
	count(policy.violation) == 0 with input as inp with data.documented_integration_roles as {"acme": ["arn:aws:iam::123456789012:role/admin"]}
}

test_vendor_id_missing if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/tags/VendorId", "value": ""}])
	policy.violation[{"id": "vendor_id_tag_missing"}] with input as inp
}

test_kms_rotation_wildcard if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/kms_key_id", "value": "aws/secretsmanager"}, {"op": "replace", "path": "/config/rotation_enabled", "value": false}, {"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "*"}])
	policy.violation[{"id": "aws_managed_default_kms_key"}] with input as inp
	policy.violation[{"id": "rotation_disabled"}] with input as inp
	policy.violation[{"id": "principal_wildcard"}] with input as inp
}

test_rotation_overdue if policy.violation[{"id": "rotation_overdue"}] with input as base_secret with time.now_ns as 1796083200000000000

test_role_and_action_checks if {
	policy.violation[{"id": "vendor_integration_role_not_documented"}] with input as base_secret
	policy.violation[{"id": "principal_outside_integration_role_set"}] with input as base_secret with data.documented_integration_roles as {"acme": ["arn:aws:iam::123456789012:role/other"]}
	policy.violation[{"id": "excess_actions"}] with input as base_secret with data.documented_integration_roles as {"acme": ["arn:aws:iam::123456789012:role/admin"]}
}

test_deny_principals_do_not_emit_scope_violations if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "*"}, {"op": "replace", "path": "/config/resource_policy/principals/0/effect", "value": "Deny"}])
	count(policy.violation) == 0 with input as inp with data.documented_integration_roles as {"acme": ["arn:aws:iam::123456789012:role/admin"]}
}

test_no_policy_passes_policy_checks if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy_present", "value": false}])
	count(policy.violation) == 0 with input as inp
}
