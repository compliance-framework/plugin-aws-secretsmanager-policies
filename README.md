# AWS ELBv2 listener policies

Standalone OPA/Rego policy bundle for listener evidence emitted by the `aws-elbv2` Compliance Framework plugin.

## Input schema

Each policy evaluates documents where `input.resource.type == "listener"`.

```json
{
  "schema_version": "v1",
  "source": "aws-elbv2",
  "account": { "account_id": "123456789012" },
  "region": { "name": "us-east-1" },
  "resource": {
    "id": "...listener/app/my-alb/abc/def",
    "arn": "arn:aws:elasticloadbalancing:...:listener/app/my-alb/abc/def",
    "type": "listener"
  },
  "config": {
    "listener_arn": "arn:aws:elasticloadbalancing:...:listener/app/my-alb/abc/def",
    "load_balancer_arn": "arn:aws:elasticloadbalancing:...:loadbalancer/app/my-alb/abc",
    "protocol": "HTTPS",
    "port": 443,
    "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
    "certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/abc"
  }
}
```

Certificate expiry and renewal are intentionally out of scope for this bundle and are handled by ACM policy bundles.

## Implemented policy packages

| Package | Purpose | Metric ID | Controls |
| --- | --- | --- | --- |
| `compliance_framework.elbv2_listener_https_enforcement` | Flags plaintext `HTTP`, `TCP`, `UDP`, or `TCP_UDP` listeners unless explicitly allowed. | `ACM_TLS_ENDPOINTS` | `ctrl-cc6-2-014`, `ctrl-cc6-2-018`, `ctrl-cc6-3-004`, `ctrl-cc6-7-001`, `ctrl-cc6-7-004`, `ctrl-cc6-7-007`, `ctrl-cc6-7-009`, `ctrl-cc6-7-010` |
| `compliance_framework.elbv2_tls_policy_approved` | Flags `HTTPS` or `TLS` listeners whose `ssl_policy` is not approved. | `ACM_TLS_ENDPOINTS` | `ctrl-cc6-7-007`, `ctrl-cc6-7-008`, `ctrl-cc6-7-010`, `ctrl-cc6-7-011` |
| `compliance_framework.elbv2_certificate_in_use` | Flags `HTTPS` or `TLS` listeners with no certificate ARN. | `ACM_TLS_ENDPOINTS` | `ctrl-cc6-7-007`, `ctrl-cc6-7-008`, `ctrl-cc6-7-010` |
| `compliance_framework.elbv2_information_movement` | Flags listener protocols or ports outside configured approved lists. | `ACM_TLS_ENDPOINTS` | `ctrl-cc6-7-002`, `ctrl-cc6-7-005`, `ctrl-cc6-7-008`, `ctrl-cc6-7-011` |

All policies skip non-`listener` records. Policies with no meaningful TLS or information-movement evaluation for Gateway Load Balancer listeners skip `GENEVE`.

## Policy data

Configurable policy defaults are stored in `policies/data.json` and may be overridden by the `policy_data` plugin as flattened data parameters.

| Name | Default | Description |
| --- | --- | --- |
| `data.approved_ssl_policies` | `["ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-TLS-1-2-Ext-2018-06"]` | SSL policy names allowed for `HTTPS` and `TLS` listeners. |
| `data.allowed_plaintext_listener_arns` | `[]` | Listener ARNs allowed to use plaintext `HTTP`, `TCP`, `UDP`, or `TCP_UDP`. |
| `data.approved_listener_protocols` | `[]` | Approved listener protocols. If omitted or empty, protocol checks pass. |
| `data.approved_listener_ports` | `[]` | Approved listener ports. Empty means unrestricted. |

## Testing

```shell
opa test policies
opa check policies
```

## Bundling

```shell
make build
```
