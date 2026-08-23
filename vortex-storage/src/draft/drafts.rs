use async_trait::async_trait;

use crate::draft::record::DraftRecord;
use crate::error::Result;
use crate::time::stamp::Stamp;

#[async_trait]
pub trait Drafts: Send + Sync {
    async fn of_member(&self, user_id: i64, room_id: i64) -> Result<Option<DraftRecord>>;

    async fn save(&self, draft: &DraftRecord) -> Result<()>;

    async fn clear(&self, user_id: i64, room_id: i64) -> Result<bool>;

    async fn forget_untouched_since(&self, cutoff: Stamp) -> Result<u64>;
}
