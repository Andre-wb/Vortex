use async_trait::async_trait;

use crate::error::Result;
use crate::health::facts::{LivenessFacts, ReadinessFacts};

#[async_trait]
pub trait NodeFactsSource: Send + Sync {
    async fn liveness(&self) -> Result<LivenessFacts>;

    async fn readiness(&self) -> Result<ReadinessFacts>;
}
