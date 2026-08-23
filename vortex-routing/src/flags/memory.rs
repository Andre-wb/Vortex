use std::collections::BTreeMap;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::error::Result;
use crate::handler::decision::Handler;
use crate::ports::route_flags::RouteFlags;
use crate::route::name::RouteName;

#[derive(Default)]
pub struct MemoryRouteFlags {
    pointed: Mutex<BTreeMap<RouteName, Handler>>,
}

impl MemoryRouteFlags {
    pub fn new() -> Self {
        MemoryRouteFlags::default()
    }
}

#[async_trait]
impl RouteFlags for MemoryRouteFlags {
    async fn handler(&self, route: &RouteName) -> Result<Option<Handler>> {
        Ok(self.pointed.lock().get(route).copied())
    }

    async fn point(&self, route: &RouteName, handler: Handler) -> Result<()> {
        self.pointed.lock().insert(route.clone(), handler);
        Ok(())
    }

    async fn clear(&self, route: &RouteName) -> Result<bool> {
        Ok(self.pointed.lock().remove(route).is_some())
    }
}
