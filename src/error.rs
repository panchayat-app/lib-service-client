use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JWT validation failed: {0}")]
    Token(String),

    #[error("Core returned HTTP {status}: {message}")]
    Api { status: u16, message: String },

    #[error("propagation failed: {0}")]
    Propagation(String),

    #[error("cache lock was poisoned")]
    Lock,
}

pub type Result<T> = std::result::Result<T, ClientError>;
