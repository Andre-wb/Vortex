use async_trait::async_trait;
use axum::body::Body;
use http::{Request, Response};

use crate::error::Result;

#[async_trait]
pub trait Relay: Send + Sync {
    async fn relay(&self, request: Request<Body>) -> Result<Response<Body>>;
}
