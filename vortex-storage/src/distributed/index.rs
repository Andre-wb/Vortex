use async_trait::async_trait;

use crate::distributed::file::DistributedFile;
use crate::error::Result;

#[async_trait]
pub trait DistributedIndex: Send + Sync {
    async fn register(&self, file: &DistributedFile) -> Result<()>;

    async fn locate(&self, file_hash: &str) -> Result<Option<DistributedFile>>;

    async fn all(&self) -> Result<Vec<DistributedFile>>;
}
