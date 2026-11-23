//! Shared client for Panchayat service trust propagation.

pub mod client;
pub mod error;
pub mod http;
pub mod jwks;
pub mod propagation;
pub mod token;
pub mod types;

pub use client::ServiceClient;
pub use error::{ClientError, Result};
pub use propagation::PropagationHandler;
pub use types::{
    ClientConfig, IssueWorkloadTokenRequest, OutboxDeliveryStatus, RecipientCheckpoint,
    RecipientDelivery, ServiceAccessTokenClaims, SyncReport, WorkloadToken,
};
