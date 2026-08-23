use std::sync::Arc;

use crate::error::Result;
use crate::handler::decision::Handler;
use crate::ports::route_flags::RouteFlags;
use crate::route::name::RouteName;

pub const FALLBACK: Handler = Handler::Python;

pub struct RouteFlagService {
    flags: Arc<dyn RouteFlags>,
}

impl RouteFlagService {
    pub fn new(flags: Arc<dyn RouteFlags>) -> Self {
        RouteFlagService { flags }
    }

    pub async fn resolve(&self, route: &RouteName) -> Handler {
        match self.flags.handler(route).await {
            Ok(Some(handler)) => handler,
            Ok(None) => FALLBACK,
            Err(error) => {
                log::warn!(
                    "{error} — роут {} отдан Python по умолчанию",
                    route.as_str()
                );
                FALLBACK
            }
        }
    }

    pub async fn point(&self, route: &RouteName, handler: Handler) -> Result<()> {
        self.flags.point(route, handler).await
    }

    pub async fn clear(&self, route: &RouteName) -> Result<bool> {
        self.flags.clear(route).await
    }
}
