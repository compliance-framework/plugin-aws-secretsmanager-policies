package compliance_framework.secretsmanager_confidential_policy_scope_test

import data.compliance_framework.secretsmanager_confidential_policy_scope as policy

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

test_wildcard if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "*"}])
	policy.violation[{"id": "wildcard_principal"}] with input as inp
}

test_wildcard_in_aws_principal_array if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": {"AWS": ["*"]}}])
	policy.violation[{"id": "wildcard_principal"}] with input as inp
}

test_cross_account if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "arn:aws:iam::999999999999:role/x"}])
	policy.violation[{"id": "cross_account_principal"}] with input as inp
}

test_cross_account_skipped_when_account_id_missing if {
	inp := json.patch(base_secret, [{"op": "remove", "path": "/account/account_id"}, {"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "arn:aws:iam::999999999999:role/x"}])
	not policy.violation[{"id": "cross_account_principal"}] with input as inp
}

test_cross_account_in_aws_principal_array if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": {"AWS": ["arn:aws:iam::999999999999:role/x"]}}])
	policy.violation[{"id": "cross_account_principal"}] with input as inp
	policy.violation[{"id": "principal_outside_cleared_role_set"}] with input as inp with data.cleared_principal_arns as ["arn:aws:iam::123456789012:role/admin"]
}

test_bare_account_principals if {
	same := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "123456789012"}])
	count(policy.violation) == 0 with input as same
	cross := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "999999999999"}])
	policy.violation[{"id": "cross_account_principal"}] with input as cross
}

test_allowed_cross_account_principals_ignored_for_confidential_policy if {
	cross := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "999999999999"}])
	policy.violation[{"id": "cross_account_principal"}] with input as cross with data.allowed_cross_account_principals as ["999999999999"]
}

test_deny_principals_do_not_emit_scope_violations if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "*"}, {"op": "replace", "path": "/config/resource_policy/principals/0/effect", "value": "Deny"}])
	count(policy.violation) == 0 with input as inp
}

test_cleared_list if {
	policy.violation[{"id": "principal_outside_cleared_role_set"}] with input as base_secret with data.cleared_principal_arns as ["arn:aws:iam::123456789012:role/other"]
	count(policy.violation) == 0 with input as base_secret with data.cleared_principal_arns as ["arn:aws:iam::123456789012:role/admin"]
}

test_wildcard_not_reported_outside_cleared_role_set if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "*"}])
	policy.violation[{"id": "wildcard_principal"}] with input as inp with data.cleared_principal_arns as ["arn:aws:iam::123456789012:role/admin"]
	not policy.violation[{"id": "principal_outside_cleared_role_set"}] with input as inp with data.cleared_principal_arns as ["arn:aws:iam::123456789012:role/admin"]
}
