package compliance_framework.elbv2_certificate_in_use

# METADATA
# title: ELBv2 HTTPS/TLS listener has a certificate
# description: Checks whether HTTPS/TLS listeners have a certificate ARN configured.
# custom:
#   metric_ids:
#     - ACM_TLS_ENDPOINTS
#   controls:
#     - ctrl-cc6-7-007
#     - ctrl-cc6-7-008
#     - ctrl-cc6-7-010
risk_templates := [{
	"name": "Load balancer TLS listener has no certificate",
	"title": "TLS Listener Cannot Establish Authenticated Encryption Without a Certificate",
	"statement": "An HTTPS or TLS listener without a certificate cannot present an expected identity to clients. Missing certificate configuration can break encrypted service paths or cause clients to fall back to less secure endpoints.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-295",
		"title": "Improper Certificate Validation",
		"url": "https://cwe.mitre.org/data/definitions/295.html",
	}],
	"remediation": {
		"title": "Attach a certificate to the listener",
		"description": "Configure each HTTPS or TLS listener with a valid ACM certificate. Certificate expiry and renewal are evaluated by ACM policies.",
		"tasks": [
			{"title": "Issue or import the required ACM certificate"},
			{"title": "Attach the certificate to the HTTPS or TLS listener"},
			{"title": "Verify the listener presents the expected certificate"},
		],
	},
}]

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
listener_arn := object.get(config, "listener_arn", "unknown")
protocol := upper(object.get(config, "protocol", ""))
certificate_arn := object.get(config, "certificate_arn", "")

skip_reason := sprintf("Resource type %q is not a listener; this policy only applies to listener records.", [resource_type]) if {
	resource_type != "listener"
}

is_tls_listener if {
	resource_type == "listener"
	protocol in {"HTTPS", "TLS"}
}

title := sprintf("Validate certificate use for listener %s", [listener_arn])
description := sprintf("Listener %s certificate ARN is %q.", [listener_arn, certificate_arn])

violation[{"id": "certificate_missing"}] if {
	is_tls_listener
	certificate_arn == ""
}
