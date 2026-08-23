use async_trait::async_trait;

use crate::error::Result;
use crate::handler::decision::Handler;
use crate::route::name::RouteName;

#[async_trait]
pub trait RouteFlags: Send + Sync {
    async fn handler(&self, route: &RouteName) -> Result<Option<Handler>>;

    async fn point(&self, route: &RouteName, handler: Handler) -> Result<()>;

    async fn clear(&self, route: &RouteName) -> Result<bool>;
}
