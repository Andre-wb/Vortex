use std::sync::Arc;

use vortex_redis::backbone::RedisBackbone;
use vortex_redis::routing::route_flags::RedisRouteFlags;
use vortex_routing::flags::absent::AbsentRouteFlags;
use vortex_routing::flags::memory::MemoryRouteFlags;
use vortex_routing::flags::service::RouteFlagService;
use vortex_routing::ports::route_flags::RouteFlags;

use crate::error::{Result, ServerError};
use crate::health::upstream_facts::UpstreamNodeFacts;
use crate::metrics::recorder::EdgeMetrics;
use crate::proxy::gateway::Gateway;
use crate::proxy::upstream_client::UpstreamClient;
use crate::settings::server::ServerSettings;
use crate::state::{ServerState, SharedState};

pub async fn assemble(settings: ServerSettings) -> Result<SharedState> {
    let upstream = Arc::new(UpstreamClient::new(settings.upstream.clone())?);
    let facts = Arc::new(UpstreamNodeFacts::new(
        upstream.client().clone(),
        settings.upstream.clone(),
    ));
    let metrics =
        Arc::new(EdgeMetrics::new().map_err(|error| ServerError::Metrics(error.to_string()))?);
    let flags = RouteFlagService::new(flag_store(&settings).await);

    Ok(Arc::new(ServerState {
        settings,
        flags,
        gateway: Gateway::new(upstream),
        facts,
        metrics,
    }))
}

async fn flag_store(settings: &ServerSettings) -> Arc<dyn RouteFlags> {
    if !settings.backbone.is_configured() {
        log::info!("[server] Redis не настроен — пер-роут флаги в памяти процесса");
        return Arc::new(MemoryRouteFlags::new());
    }
    match RedisBackbone::connect_async(settings.backbone.clone()).await {
        Ok(backbone) => {
            log::info!("[server] пер-роут флаги в Redis — переключение видят все воркеры");
            Arc::new(RedisRouteFlags::new(backbone))
        }
        Err(error) => {
            log::error!("[server] Redis недоступен ({error}) — все роуты уходят в Python");
            Arc::new(AbsentRouteFlags::new())
        }
    }
}
