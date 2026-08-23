use async_trait::async_trait;

use crate::error::Result;
use crate::push::unified::subscription::UnifiedSubscription;

#[async_trait]
pub trait UnifiedPushDirectory: Send + Sync {
    async fn of_user(&self, user_id: i64) -> Result<Vec<UnifiedSubscription>>;

    async fn register(&self, subscription: &UnifiedSubscription) -> Result<()>;

    async fn unregister(&self, user_id: i64, endpoint: &str) -> Result<bool>;

    async fn record_delivery(
        &self,
        user_id: i64,
        endpoint: &str,
        failures: i64,
        active: bool,
    ) -> Result<()>;
}
