use reqwest::Response;

use crate::error::ClientError;

pub async fn parse_error(response: Response) -> ClientError {
    let status = response.status().as_u16();
    let message = response.text().await.unwrap_or_default();
    ClientError::Api { status, message }
}

pub fn bearer(value: &str) -> String {
    format!("Bearer {value}")
}
