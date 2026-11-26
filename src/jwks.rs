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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn spawn_jwks_server(body: String) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{addr}/jwks.json"), handle)
    }

    #[test]
    fn default_url_is_derived_from_core_base_url() {
        let config = ClientConfig::new("http://core.example/", uuid::Uuid::now_v7());
        let cache = JwksCache::new(&config, reqwest::Client::new());
        assert_eq!(cache.url(), "http://core.example/.well-known/jwks.json");
    }

    #[tokio::test]
    async fn fetches_jwks_once_and_serves_cached_keys() {
        let body =
            r#"{"keys":[{"kty":"oct","kid":"test-kid","alg":"HS256","k":"c2VjcmV0"}]}"#.to_owned();
        let (url, server) = spawn_jwks_server(body);

        let mut config = ClientConfig::new("http://core.example", uuid::Uuid::now_v7());
        config.jwks_url = Some(url);
        let cache = JwksCache::new(&config, reqwest::Client::new());

        let first = cache.get().await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].common.key_id.as_deref(), Some("test-kid"));

        // The test server only accepts one connection. A second cache miss
        // would fail to connect, so successful reads prove the cache was used.
        let second = cache.get().await.unwrap();
        assert_eq!(second.len(), 1);
        server.join().unwrap();
    }
}
