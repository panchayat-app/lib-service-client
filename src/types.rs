use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccessTokenClaims {
    pub iss: String,
    pub sub: Uuid,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub nbf: i64,
    #[serde(default)]
    pub jti: Uuid,
    pub authorization_version: i64,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
}

impl ServiceAccessTokenClaims {
    pub fn certificate_thumbprint(&self) -> Option<&str> {
        self.cnf.as_ref().map(|claim| claim.x5t_s256.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnfClaim {
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboxDeliveryStatus {
    Pending,
    Delivered,
    Acknowledged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientCheckpoint {
    pub recipient_service_id: Uuid,
    pub latest_revision: i64,
    pub acknowledged_revision: i64,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientDelivery {
    pub id: Uuid,
    pub event_id: Uuid,
    pub recipient_service_id: Uuid,
    pub recipient_revision: i64,
    pub status: OutboxDeliveryStatus,
    pub attempt_count: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,

    // Optional event summary. Core may include these fields when listing
    // recipient deliveries; clients should tolerate their absence.
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub aggregate_type: Option<String>,
    #[serde(default)]
    pub aggregate_id: Option<Uuid>,
    #[serde(default)]
    pub aggregate_version: Option<i64>,
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueWorkloadTokenRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<Uuid>,
    #[serde(default, alias = "audience", alias = "aud")]
    pub audience: String,
    #[serde(default, alias = "operations", alias = "scopes")]
    pub operations: Vec<String>,
    #[serde(
        default,
        alias = "ttl_seconds",
        alias = "ttl",
        skip_serializing_if = "Option::is_none"
    )]
    pub ttl_seconds: Option<i64>,
    #[serde(
        default,
        alias = "certificate_pem",
        alias = "client_certificate",
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Clone)]
pub struct WorkloadToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub expires_at: DateTime<Utc>,
}

impl From<WorkloadTokenResponse> for WorkloadToken {
    fn from(value: WorkloadTokenResponse) -> Self {
        Self {
            access_token: value.access_token,
            token_type: value.token_type,
            expires_in: value.expires_in,
            expires_at: Utc::now() + chrono::Duration::seconds(value.expires_in),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub core_base_url: String,
    pub jwks_url: Option<String>,
    pub service_id: Uuid,
    pub principal_id: Option<Uuid>,
    pub default_audience: String,
    pub client_cert_pem: Option<String>,
    pub client_key_pem: Option<String>,
    pub access_token: Option<String>,
    pub token_refresh_skew_seconds: i64,
    pub default_operations: Vec<String>,
    pub checkpoint_max_age_seconds: i64,
    pub checkpoint_future_skew_seconds: i64,
}

impl ClientConfig {
    pub fn new(core_base_url: impl Into<String>, service_id: Uuid) -> Self {
        Self {
            core_base_url: core_base_url.into(),
            jwks_url: None,
            service_id,
            principal_id: None,
            default_audience: "core".to_owned(),
            client_cert_pem: None,
            client_key_pem: None,
            access_token: None,
            token_refresh_skew_seconds: 30,
            default_operations: vec![
                "service_trust.recipient.read".to_owned(),
                "service_trust.recipient.acknowledge".to_owned(),
            ],
            checkpoint_max_age_seconds: 300,
            checkpoint_future_skew_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SyncReport {
    pub deliveries_seen: usize,
    pub deliveries_applied: usize,
    pub deliveries_acknowledged: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn recipient_delivery_deserializes_event_summary() {
        let id = Uuid::now_v7();
        let event_id = Uuid::now_v7();
        let service_id = Uuid::now_v7();
        let json = serde_json::json!({
            "id": id,
            "event_id": event_id,
            "recipient_service_id": service_id,
            "recipient_revision": 7,
            "status": "pending",
            "attempt_count": 1,
            "next_attempt_at": "2026-01-01T00:00:00Z",
            "last_attempt_at": null,
            "delivered_at": null,
            "acknowledged_at": null,
            "last_error": null,
            "event_type": "service_principal_updated",
            "aggregate_type": "service_principal",
            "aggregate_id": id,
            "aggregate_version": 3,
            "payload": {"authorization_version": 3}
        });

        let delivery: RecipientDelivery = serde_json::from_value(json).unwrap();
        assert_eq!(delivery.status, OutboxDeliveryStatus::Pending);
        assert_eq!(delivery.aggregate_version, Some(3));
    }

    #[test]
    fn client_config_defaults_are_safe() {
        let config = ClientConfig::new("http://core.example", Uuid::now_v7());
        assert_eq!(config.default_audience, "core");
        assert!(config.access_token.is_none());
        assert_eq!(config.checkpoint_max_age_seconds, 300);
        assert!(
            config
                .default_operations
                .iter()
                .any(|value| value == "service_trust.recipient.read")
        );
    }
}
