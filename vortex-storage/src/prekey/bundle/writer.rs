use async_trait::async_trait;
use vortex_proto::prekey::bundle::stored::StoredBundle;

use crate::error::Result;
use crate::time::stamp::Stamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveOutcome {
    Created(i64),
    Updated(i64),
}

impl SaveOutcome {
    pub fn id(&self) -> i64 {
        match self {
            SaveOutcome::Created(id) | SaveOutcome::Updated(id) => *id,
        }
    }
}

#[async_trait]
pub trait BundleWriter: Send + Sync {
    async fn save(&self, user_id: i64, bundle: &StoredBundle, at: Stamp) -> Result<SaveOutcome>;
}
