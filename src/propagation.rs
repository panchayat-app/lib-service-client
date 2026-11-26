use async_trait::async_trait;

use crate::Result;
use crate::types::{RecipientCheckpoint, RecipientDelivery};

/// A recipient-side store that durably applies service-trust deliveries.
///
/// Implementations must update the applied revision and the delivered state in
/// the same transaction. `sync_propagation` calls `apply_delivery` before it
/// acknowledges a delivery to Core, so an error leaves the delivery unacknowledged
/// and retryable.
#[async_trait]
pub trait PropagationHandler: Send + Sync {
    /// Highest contiguous recipient revision durably applied locally.
    async fn applied_revision(&self) -> Result<i64>;

    /// Apply one delivery. The operation must be idempotent.
    async fn apply_delivery(&self, delivery: &RecipientDelivery) -> Result<()>;

    /// Record the most recently observed checkpoint, including its issue time.
    async fn record_checkpoint(&self, checkpoint: &RecipientCheckpoint) -> Result<()>;
}
