use std::sync::Arc;

use async_trait::async_trait;
use fred::prelude::*;
use vortex_routing::error::{Result, RoutingError};
use vortex_routing::handler::decision::Handler;
use vortex_routing::ports::route_flags::RouteFlags;
use vortex_routing::route::name::RouteName;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;

pub const DOMAIN: &str = "server";
pub const BUCKET: &str = "route";

pub struct RedisRouteFlags {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisRouteFlags {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisRouteFlags { backbone, space }
    }

    fn key(&self, route: &RouteName) -> String {
        self.space.member_key(BUCKET, route.as_str())
    }
}

#[async_trait]
impl RouteFlags for RedisRouteFlags {
    async fn handler(&self, route: &RouteName) -> Result<Option<Handler>> {
        let key = self.key(route);
        let stored: Option<String> = self
            .backbone
            .execute_async("чтение пер-роут флага", |pool| async move {
                pool.get(&key).await
            })
            .await
            .map_err(|_| RoutingError::Unavailable)?;
        Ok(stored.as_deref().and_then(Handler::parse))
    }

    async fn point(&self, route: &RouteName, handler: Handler) -> Result<()> {
        let key = self.key(route);
        let value = handler.as_str().to_string();
        self.backbone
            .execute_async("запись пер-роут флага", |pool| async move {
                pool.set(&key, value, None, None, false).await
            })
            .await
            .map_err(|_| RoutingError::Unavailable)
    }

    async fn clear(&self, route: &RouteName) -> Result<bool> {
        let key = self.key(route);
        let removed: i64 = self
            .backbone
            .execute_async("снятие пер-роут флага", |pool| async move {
                pool.del(&key).await
            })
            .await
            .map_err(|_| RoutingError::Unavailable)?;
        Ok(removed > 0)
    }
}
