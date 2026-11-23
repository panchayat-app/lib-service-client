# panchayat-service-client

Shared Rust client for Panchayat service-trust propagation.

It provides:
- JWKS retrieval and in-memory caching
- RS256 service access token validation
- Workload token issuance and lazy refresh
- Recipient checkpoint, delivery, and acknowledgement calls
- A propagation callback for applying principal authorization versions

Core remains the control plane. Recipients use this crate to poll Core and apply deliveries locally.
