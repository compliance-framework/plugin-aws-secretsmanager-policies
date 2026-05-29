package compliance_framework.secretsmanager_vendor_credential_policy_scope_test

import data.compliance_framework.secretsmanager_vendor_credential_policy_scope as policy

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
	count(policy.violation) == 0 with input as inp
}

test_wildcard if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "*"}])
	policy.violation[{"id": "vendor_principal_wildcard"}] with input as inp
}

test_excess_actions if policy.violation[{"id": "vendor_principal_excess_actions"}] with input as base_secret

test_scalar_excess_action if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/action", "value": "secretsmanager:DeleteSecret"}])
	policy.violation[{"id": "vendor_principal_excess_actions"}] with input as inp
}

test_cross_account if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "arn:aws:iam::999999999999:role/vendor"}, {"op": "replace", "path": "/config/resource_policy/principals/0/action", "value": ["secretsmanager:GetSecretValue"]}])
	policy.violation[{"id": "vendor_principal_cross_account_undocumented"}] with input as inp
	count(policy.violation) == 0 with input as inp with data.allowed_vendor_partner_accounts as ["999999999999"]
}

test_cross_account_skipped_when_account_id_missing if {
	inp := json.patch(base_secret, [{"op": "remove", "path": "/account/account_id"}, {"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "arn:aws:iam::999999999999:role/vendor"}, {"op": "replace", "path": "/config/resource_policy/principals/0/action", "value": ["secretsmanager:GetSecretValue"]}])
	not policy.violation[{"id": "vendor_principal_cross_account_undocumented"}] with input as inp
}

test_bare_account_principals if {
	same := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "123456789012"}, {"op": "replace", "path": "/config/resource_policy/principals/0/action", "value": ["secretsmanager:GetSecretValue"]}])
	count(policy.violation) == 0 with input as same
	cross := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "999999999999"}, {"op": "replace", "path": "/config/resource_policy/principals/0/action", "value": ["secretsmanager:GetSecretValue"]}])
	policy.violation[{"id": "vendor_principal_cross_account_undocumented"}] with input as cross
	count(policy.violation) == 0 with input as cross with data.allowed_vendor_partner_accounts as ["999999999999"]
}

test_deny_principals_do_not_emit_scope_violations if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "*"}, {"op": "replace", "path": "/config/resource_policy/principals/0/effect", "value": "Deny"}])
	count(policy.violation) == 0 with input as inp
}

test_no_policy_passes if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy_present", "value": false}])
	count(policy.violation) == 0 with input as inp
}
