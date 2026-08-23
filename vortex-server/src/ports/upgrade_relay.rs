use async_trait::async_trait;
use axum::body::Body;
use http::Request;

use crate::error::Result;
use crate::proxy::upgrade::outcome::UpgradeOutcome;

#[async_trait]
pub trait UpgradeRelay: Send + Sync {
    async fn open(&self, request: Request<Body>) -> Result<UpgradeOutcome>;
}
