use std::sync::Mutex;

use jsonwebtoken::jwk::Jwk;
use reqwest::Client;

use crate::error::{ClientError, Result};
use crate::types::ClientConfig;

#[derive(Debug)]
pub struct JwksCache {
    url: String,
    client: Client,
    keys: Mutex<Option<Vec<Jwk>>>,
}

impl JwksCache {
    pub fn new(config: &ClientConfig, client: Client) -> Self {
        let url = config.jwks_url.clone().unwrap_or_else(|| {
            format!(
                "{}/.well-known/jwks.json",
                config.core_base_url.trim_end_matches('/')
            )
        });
        Self {
            url,
            client,
            keys: Mutex::new(None),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn get(&self) -> Result<Vec<Jwk>> {
        if let Some(keys) = self.keys.lock().map_err(|_| ClientError::Lock)?.clone()
            && !keys.is_empty()
        {
            return Ok(keys);
        }

        self.fetch().await
    }

    pub async fn get_for_kid(&self, kid: Option<&str>) -> Result<Vec<Jwk>> {
        let keys = self.get().await?;
        if let Some(kid) = kid {
            if keys
                .iter()
                .any(|key| key.common.key_id.as_deref() == Some(kid))
            {
                return Ok(keys);
            }
            // Unknown key id: force one refresh.
            return self.fetch().await;
        }
        Ok(keys)
    }

    async fn fetch(&self) -> Result<Vec<Jwk>> {
        #[derive(serde::Deserialize)]
        struct JwksDocument {
            keys: Vec<serde_json::Value>,
        }

        let document: JwksDocument = self
            .client
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let mut keys = Vec::with_capacity(document.keys.len());
        for value in document.keys {
            let key: Jwk = serde_json::from_value(value)?;
            keys.push(key);
        }

        *self.keys.lock().map_err(|_| ClientError::Lock)? = Some(keys.clone());
        Ok(keys)
    }
}
