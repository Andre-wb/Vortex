use async_trait::async_trait;

use crate::error::Result;

#[async_trait]
pub trait ScopeGrants: Send + Sync {
    async fn granted_to(&self, bot_id: i64) -> Result<Vec<String>>;

    async fn replace(&self, bot_id: i64, scopes: &[String]) -> Result<()>;
}
