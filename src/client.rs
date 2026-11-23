use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{Duration, Utc};
use reqwest::Client;
use uuid::Uuid;

use crate::error::{ClientError, Result};
use crate::http;
use crate::jwks::JwksCache;
use crate::propagation::PropagationHandler;
use crate::token;
use crate::types::{
    ClientConfig, IssueWorkloadTokenRequest, OutboxDeliveryStatus, RecipientCheckpoint,
    RecipientDelivery, ServiceAccessTokenClaims, SyncReport, WorkloadToken, WorkloadTokenResponse,
};

#[derive(Clone, PartialEq, Eq, Hash)]
struct TokenCacheKey {
    audience: String,
    operations: Vec<String>,
}

pub struct ServiceClient {
    config: ClientConfig,
    http: Client,
    jwks: JwksCache,
    token_cache: Mutex<HashMap<TokenCacheKey, WorkloadToken>>,
}

impl ServiceClient {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let http = Client::builder().build().map_err(ClientError::Http)?;
        let jwks = JwksCache::new(&config, http.clone());
        Ok(Self {
            config,
            http,
            jwks,
            token_cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn jwks_url(&self) -> &str {
        self.jwks.url()
    }

    pub async fn jwks(&self) -> Result<Vec<jsonwebtoken::jwk::Jwk>> {
        self.jwks.get().await
    }

    pub async fn validate_access_token(
        &self,
        token: &str,
        expected_audience: Option<&str>,
    ) -> Result<ServiceAccessTokenClaims> {
        let kid = token::decode_header_kid(token)?;
        let keys = self.jwks.get_for_kid(kid.as_deref()).await?;

        let jwk = if let Some(kid) = kid.as_deref() {
            keys.into_iter()
                .find(|key| key.common.key_id.as_deref() == Some(kid))
                .ok_or_else(|| ClientError::Token("unknown signing key id".to_owned()))?
        } else if keys.len() == 1 {
            keys.into_iter().next().expect("checked length")
        } else {
            return Err(ClientError::Token("token is missing a key id".to_owned()));
        };

        token::validate_with_jwk(token, &jwk, expected_audience, Some("panchayat-core"))
    }

    pub async fn issue_workload_token(
        &self,
        mut request: IssueWorkloadTokenRequest,
    ) -> Result<WorkloadToken> {
        if request.principal_id.is_none() {
            request.principal_id = self.config.principal_id;
        }
        if request.certificate_pem.is_none() {
            request.certificate_pem = self.config.client_cert_pem.clone();
        }
        if request.audience.trim().is_empty() {
            request.audience = self.config.default_audience.clone();
        }

        let principal_id = request.principal_id.or(self.config.principal_id);
        let base = self.config.core_base_url.trim_end_matches('/');
        let url = match principal_id {
            Some(id) => format!("{base}/v1/service-principals/{id}/workload-token"),
            None => format!("{base}/v1/service-workload-tokens"),
        };

        if principal_id.is_none() && request.principal_id.is_none() {
            return Err(ClientError::Config(
                "principal_id is required to issue a workload token".to_owned(),
            ));
        }

        let response = self.http.post(&url).json(&request).send().await?;
        if !response.status().is_success() {
            return Err(http::parse_error(response).await);
        }

        let body: WorkloadTokenResponse = response.json().await?;
        Ok(body.into())
    }

    pub async fn workload_token(
        &self,
        audience: Option<&str>,
        operations: Vec<String>,
        ttl_seconds: Option<i64>,
    ) -> Result<String> {
        let audience = audience
            .map(str::to_owned)
            .unwrap_or_else(|| self.config.default_audience.clone());
        let key = TokenCacheKey {
            audience: audience.clone(),
            operations: operations.clone(),
        };

        {
            let cache = self.token_cache.lock().map_err(|_| ClientError::Lock)?;
            if let Some(cached) = cache.get(&key) {
                let refresh_at =
                    cached.expires_at - Duration::seconds(self.config.token_refresh_skew_seconds);
                if Utc::now() < refresh_at {
                    return Ok(cached.access_token.clone());
                }
            }
        }

        let request = IssueWorkloadTokenRequest {
            principal_id: self.config.principal_id,
            audience,
            operations,
            ttl_seconds,
            certificate_pem: self.config.client_cert_pem.clone(),
        };
        let token = self.issue_workload_token(request).await?;
        let access_token = token.access_token.clone();

        let mut cache = self.token_cache.lock().map_err(|_| ClientError::Lock)?;
        cache.insert(key, token);
        Ok(access_token)
    }

    async fn bearer_token(&self) -> Result<String> {
        if let Some(token) = &self.config.access_token {
            return Ok(token.clone());
        }
        self.workload_token(None, Vec::new(), None).await
    }

    pub async fn checkpoint(&self) -> Result<RecipientCheckpoint> {
        let token = self.bearer_token().await?;
        let url = format!(
            "{}/v1/service-recipients/{}/checkpoint",
            self.config.core_base_url.trim_end_matches('/'),
            self.config.service_id
        );

        let response = self
            .http
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, http::bearer(&token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(http::parse_error(response).await);
        }
        let checkpoint: RecipientCheckpoint = response.json().await?;
        Ok(checkpoint)
    }

    pub async fn deliveries(&self) -> Result<Vec<RecipientDelivery>> {
        let token = self.bearer_token().await?;
        let url = format!(
            "{}/v1/service-recipients/{}/deliveries",
            self.config.core_base_url.trim_end_matches('/'),
            self.config.service_id
        );

        let response = self
            .http
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, http::bearer(&token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(http::parse_error(response).await);
        }
        let deliveries: Vec<RecipientDelivery> = response.json().await?;
        Ok(deliveries)
    }

    pub async fn acknowledge(&self, delivery_id: Uuid) -> Result<RecipientDelivery> {
        let token = self.bearer_token().await?;
        let url = format!(
            "{}/v1/service-recipients/{}/deliveries/{}/acknowledge",
            self.config.core_base_url.trim_end_matches('/'),
            self.config.service_id,
            delivery_id
        );

        let response = self
            .http
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, http::bearer(&token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(http::parse_error(response).await);
        }
        let delivery: RecipientDelivery = response.json().await?;
        Ok(delivery)
    }

    pub async fn sync_propagation(&self, handler: &dyn PropagationHandler) -> Result<SyncReport> {
        let deliveries = self.deliveries().await?;
        let mut report = SyncReport {
            deliveries_seen: deliveries.len(),
            ..SyncReport::default()
        };

        for delivery in deliveries {
            if delivery.status == OutboxDeliveryStatus::Acknowledged {
                continue;
            }

            if (delivery.aggregate_type.as_deref() == Some("service_principal")
                || delivery
                    .event_type
                    .as_deref()
                    .map(|value| value.contains("principal"))
                    .unwrap_or(false))
                && let (Some(principal_id), Some(version)) =
                    (delivery.aggregate_id, delivery.aggregate_version)
            {
                handler.apply_principal_version(principal_id, version);
            }

            self.acknowledge(delivery.id).await?;
            report.deliveries_acknowledged += 1;
        }

        Ok(report)
    }
}
