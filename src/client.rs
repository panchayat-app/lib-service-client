use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{Duration, Utc};
use reqwest::{Client, Identity};
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

const DELIVERY_PAGE_SIZE: usize = 100;

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
        let mut builder = Client::builder();

        match (
            config.client_cert_pem.as_deref(),
            config.client_key_pem.as_deref(),
        ) {
            (Some(certificate), Some(key)) => {
                let identity_pem = format!("{}\n{}\n", certificate.trim(), key.trim());
                let identity =
                    Identity::from_pem(identity_pem.as_bytes()).map_err(ClientError::Http)?;
                builder = builder.identity(identity);
            }
            (Some(_), None) => {
                return Err(ClientError::Config(
                    "client_key_pem is required when client_cert_pem is configured".to_owned(),
                ));
            }
            (None, Some(_)) => {
                return Err(ClientError::Config(
                    "client_cert_pem is required when client_key_pem is configured".to_owned(),
                ));
            }
            (None, None) => {}
        }

        let http = builder.build().map_err(ClientError::Http)?;
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
        self.validate_token(token, expected_audience, None).await
    }

    /// Validate a token and require its `cnf.x5t#S256` thumbprint to match the
    /// X.509 certificate presented by the caller. Recipients should use this
    /// method when authenticating service-to-service requests.
    pub async fn validate_access_token_for_certificate(
        &self,
        token: &str,
        expected_audience: Option<&str>,
        certificate_pem: &str,
    ) -> Result<ServiceAccessTokenClaims> {
        let fingerprint = token::certificate_fingerprint_sha256(certificate_pem)?;
        self.validate_token(token, expected_audience, Some(&fingerprint))
            .await
    }

    async fn validate_token(
        &self,
        token: &str,
        expected_audience: Option<&str>,
        expected_certificate_fingerprint: Option<&[u8]>,
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

        token::validate_with_jwk_and_certificate(
            token,
            &jwk,
            expected_audience,
            Some("panchayat-core"),
            expected_certificate_fingerprint,
        )
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

        let principal_id = request.principal_id.ok_or_else(|| {
            ClientError::Config("principal_id is required to issue a workload token".to_owned())
        })?;
        let base = self.config.core_base_url.trim_end_matches('/');
        let url = format!("{base}/v1/service-principals/{principal_id}/workload-token");

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
        if self.config.default_operations.is_empty() {
            return Err(ClientError::Config(
                "default_operations must not be empty when no access_token is configured"
                    .to_owned(),
            ));
        }
        self.workload_token(None, self.config.default_operations.clone(), None)
            .await
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
        let mut deliveries = Vec::new();
        let mut offset = 0usize;

        loop {
            let page = self.deliveries_page(DELIVERY_PAGE_SIZE, offset).await?;
            let page_len = page.len();
            deliveries.extend(page);
            if page_len < DELIVERY_PAGE_SIZE {
                break;
            }
            offset += page_len;
        }

        deliveries.sort_by_key(|delivery| delivery.recipient_revision);
        Ok(deliveries)
    }

    async fn deliveries_page(&self, limit: usize, offset: usize) -> Result<Vec<RecipientDelivery>> {
        let token = self.bearer_token().await?;
        let url = format!(
            "{}/v1/service-recipients/{}/deliveries",
            self.config.core_base_url.trim_end_matches('/'),
            self.config.service_id
        );

        let response = self
            .http
            .get(&url)
            .query(&[("limit", limit.to_string()), ("offset", offset.to_string())])
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

    /// Poll Core, apply every contiguous delivery through `handler`, and
    /// acknowledge only after the handler has durably committed it.
    ///
    /// A stale checkpoint, a revision gap, or a handler error leaves the
    /// unapplied deliveries unacknowledged and returns an error. Previously
    /// acknowledged revisions are replayed idempotently when local state is
    /// behind.
    pub async fn sync_propagation<H: PropagationHandler + ?Sized>(
        &self,
        handler: &H,
    ) -> Result<SyncReport> {
        let checkpoint = self.checkpoint().await?;
        self.validate_checkpoint(&checkpoint)?;
        handler.record_checkpoint(&checkpoint).await?;

        let mut applied_revision = handler.applied_revision().await?;
        if applied_revision > checkpoint.latest_revision {
            return Err(ClientError::Propagation(format!(
                "local applied revision {applied_revision} is ahead of Core checkpoint {}",
                checkpoint.latest_revision
            )));
        }

        let deliveries = self.deliveries().await?;
        let mut report = SyncReport {
            deliveries_seen: deliveries.len(),
            ..SyncReport::default()
        };

        for delivery in deliveries {
            if delivery.recipient_revision <= applied_revision {
                if delivery.status != OutboxDeliveryStatus::Acknowledged {
                    self.acknowledge(delivery.id).await?;
                    report.deliveries_acknowledged += 1;
                }
                continue;
            }

            let expected_revision = applied_revision + 1;
            if delivery.recipient_revision != expected_revision {
                return Err(ClientError::Propagation(format!(
                    "revision gap: expected {expected_revision}, got {}",
                    delivery.recipient_revision
                )));
            }

            handler.apply_delivery(&delivery).await?;
            applied_revision = delivery.recipient_revision;
            report.deliveries_applied += 1;

            if delivery.status != OutboxDeliveryStatus::Acknowledged {
                self.acknowledge(delivery.id).await?;
                report.deliveries_acknowledged += 1;
            }
        }

        if applied_revision < checkpoint.latest_revision {
            return Err(ClientError::Propagation(format!(
                "local applied revision {applied_revision} has not reached checkpoint {}",
                checkpoint.latest_revision
            )));
        }

        Ok(report)
    }

    fn validate_checkpoint(&self, checkpoint: &RecipientCheckpoint) -> Result<()> {
        let now = Utc::now();
        if checkpoint.issued_at
            > now + Duration::seconds(self.config.checkpoint_future_skew_seconds)
        {
            return Err(ClientError::Propagation(
                "checkpoint issue time is in the future".to_owned(),
            ));
        }
        let age = now - checkpoint.issued_at;
        if age > Duration::seconds(self.config.checkpoint_max_age_seconds) {
            return Err(ClientError::Propagation(format!(
                "checkpoint is stale: issued {} seconds ago",
                age.num_seconds()
            )));
        }
        Ok(())
    }
}
