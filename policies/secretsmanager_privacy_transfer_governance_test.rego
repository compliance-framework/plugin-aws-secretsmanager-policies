package compliance_framework.secretsmanager_privacy_transfer_governance_test

import data.compliance_framework.secretsmanager_privacy_transfer_governance as policy

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

test_missing_flow if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/tags/DataSubjectFlow", "value": ""}])
	policy.violation[{"id": "data_subject_flow_tag_missing"}] with input as inp
}

test_register_enforced if {
	policy.violation[{"id": "data_subject_flow_not_in_register"}] with input as base_secret with data.documented_data_subject_flows as ["other"]
	count(policy.violation) == 0 with input as base_secret with data.documented_data_subject_flows as ["customer-onboarding"]
}

test_cross_border if {
	policy.violation[{"id": "cross_border_principal_undocumented"}] with input as base_secret with data.account_id_to_region as {"123456789012": "eu-west-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
	count(policy.violation) == 0 with input as base_secret with data.account_id_to_region as {"123456789012": "us-east-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
}

test_cross_border_principal_array if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": {"AWS": ["arn:aws:iam::999999999999:role/vendor"]}}])
	policy.violation[{"id": "cross_border_principal_undocumented"}] with input as inp with data.account_id_to_region as {"999999999999": "eu-west-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
}

test_cross_border_principal_array_with_multiple_regions if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": {"AWS": ["arn:aws:iam::111111111111:role/vendor", "arn:aws:iam::222222222222:role/vendor"]}}])
	policy.violation[{"id": "cross_border_principal_undocumented"}] with input as inp with data.account_id_to_region as {"111111111111": "us-east-1", "222222222222": "eu-west-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
}

test_bare_account_principals if {
	same := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "123456789012"}])
	count(policy.violation) == 0 with input as same with data.account_id_to_region as {"123456789012": "us-east-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
	cross := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "999999999999"}])
	policy.violation[{"id": "cross_border_principal_undocumented"}] with input as cross with data.account_id_to_region as {"999999999999": "eu-west-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
}

test_unmapped_cross_account_principal_fails if {
	bare_cross := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "999999999999"}])
	policy.violation[{"id": "cross_border_principal_undocumented"}] with input as bare_cross with data.account_id_to_region as {"111111111111": "us-east-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
	arn_cross := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "arn:aws:iam::999999999999:role/vendor"}])
	policy.violation[{"id": "cross_border_principal_undocumented"}] with input as arn_cross with data.account_id_to_region as {"111111111111": "us-east-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
}

test_unmapped_cross_account_principal_skipped_when_account_id_missing if {
	inp := json.patch(base_secret, [{"op": "remove", "path": "/account/account_id"}, {"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "arn:aws:iam::999999999999:role/vendor"}])
	not policy.violation[{"id": "cross_border_principal_undocumented"}] with input as inp with data.account_id_to_region as {"111111111111": "us-east-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
}

test_unmapped_same_account_principal_passes if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "123456789012"}])
	count(policy.violation) == 0 with input as inp with data.account_id_to_region as {"111111111111": "us-east-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
}

test_deny_principals_do_not_emit_scope_violations if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/config/resource_policy/principals/0/principal", "value": "999999999999"}, {"op": "replace", "path": "/config/resource_policy/principals/0/effect", "value": "Deny"}])
	count(policy.violation) == 0 with input as inp with data.account_id_to_region as {"999999999999": "eu-west-1"} with data.allowed_pi_transfer_regions as ["us-east-1"]
}

test_non_pi_skipped if {
	inp := json.patch(base_secret, [{"op": "replace", "path": "/tags/PrivacyScope", "value": "none"}])
	count(policy.violation) == 0 with input as inp
	policy.skip_reason with input as inp
}
