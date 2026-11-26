# panchayat-service-client

Shared Rust client for Panchayat service-trust propagation.

It provides:

- JWKS retrieval and in-memory caching
- ES256 service access token validation against Core's published P-256 JWKS
- Certificate binding checks for the `cnf.x5t#S256` claim
- mTLS client identity construction from PEM certificate and key
- Workload token issuance and lazy refresh
- Recipient checkpoint, delivery, and acknowledgement calls
- An async propagation callback for durably applying authorization versions

Core remains the control plane. Recipients use this crate to poll Core and apply deliveries locally. They never read Core's database.

## Configuration

`ClientConfig` carries the Core base URL, service and principal identifiers, the workload certificate and private key, and the default recipient operations:

```rust
use panchayat_service_client::ClientConfig;

let mut config = ClientConfig::new("https://core.example", service_id);
config.principal_id = Some(principal_id);
config.default_audience = "core".to_owned();
config.client_cert_pem = Some(certificate_pem);
config.client_key_pem = Some(private_key_pem);
config.default_operations = vec![
    "service_trust.recipient.read".to_owned(),
    "service_trust.recipient.acknowledge".to_owned(),
];
```

When both certificate and key are set, the client presents them as a real mTLS identity on every HTTPS request. The certificate must be the same certificate Core registered for the principal; the resulting token is bound to that certificate's SHA-256 thumbprint. TLS termination must preserve the client certificate for Core, typically through `x-client-cert` or `x-forwarded-client-cert`.

## Validation

Use `validate_access_token_for_certificate` when authenticating a service-to-service request. It verifies the ES256 signature, issuer, audience, expiry, and the certificate thumbprint. It does not decide whether the token's authorization version is still current; the recipient must compare that claim with its own applied state:

```rust
let claims = client
    .validate_access_token_for_certificate(&token, Some("core"), &presented_certificate_pem)
    .await?;
```

`validate_access_token` performs the same cryptographic checks without requiring certificate binding and is intended only for callers that already have another authenticated channel.

## Propagation

Implement `PropagationHandler` so `apply_delivery` commits the principal version, applied revision, and any domain state in one transaction. `sync_propagation` applies each contiguous delivery before acknowledging it, rejects revision gaps, and refuses stale checkpoints:

```rust
let report = client.sync_propagation(&handler).await?;
```

If a handler returns an error, the delivery remains unacknowledged and is retried. Unsupported event types should fail closed rather than be acknowledged.
