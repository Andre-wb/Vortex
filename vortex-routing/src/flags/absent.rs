use async_trait::async_trait;

use crate::error::{Result, RoutingError};
use crate::handler::decision::Handler;
use crate::ports::route_flags::RouteFlags;
use crate::route::name::RouteName;

#[derive(Default)]
pub struct AbsentRouteFlags;

impl AbsentRouteFlags {
    pub fn new() -> Self {
        AbsentRouteFlags
    }
}

#[async_trait]
impl RouteFlags for AbsentRouteFlags {
    async fn handler(&self, _route: &RouteName) -> Result<Option<Handler>> {
        Err(RoutingError::Unavailable)
    }

    async fn point(&self, _route: &RouteName, _handler: Handler) -> Result<()> {
        Err(RoutingError::Unavailable)
    }

    async fn clear(&self, _route: &RouteName) -> Result<bool> {
        Err(RoutingError::Unavailable)
    }
}
