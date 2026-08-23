use async_trait::async_trait;

use crate::error::Result;
use crate::time::stamp::Stamp;

#[async_trait]
pub trait InlineResults: Send + Sync {
    async fn of_bot(&self, bot_id: i64) -> Result<Option<String>>;

    async fn remember(&self, bot_id: i64, results: &str, at: Stamp) -> Result<()>;

    async fn keep_newest(&self, ceiling: i64) -> Result<u64>;
}
