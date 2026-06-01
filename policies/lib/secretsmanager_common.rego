package ccf_libs.secretsmanager_common

pending_deletion(record) if {
	config := object.get(record, "config", {})
	object.get(config, "deleted_date", "") != ""
}

pending_deletion_skip_reason(record) := reason if {
	config := object.get(record, "config", {})
	resource := object.get(record, "resource", {})
	secret_arn := object.get(config, "secret_arn", object.get(resource, "arn", "unknown"))
	deleted_date := object.get(config, "deleted_date", "")
	deleted_date != ""
	reason := sprintf("Secret %s is pending deletion (deleted_date=%q); steady-state posture is not evaluated for secrets scheduled for deletion.", [secret_arn, deleted_date])
}
