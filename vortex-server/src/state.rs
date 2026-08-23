use std::sync::Arc;

use crate::metrics::recorder::EdgeMetrics;
use crate::ports::facts::NodeFactsSource;
use crate::proxy::gateway::Gateway;
use crate::proxy::upstream_client::UpstreamClient;
use crate::settings::server::ServerSettings;
use vortex_routing::flags::service::RouteFlagService;

pub struct ServerState {
    pub settings: ServerSettings,
    pub flags: RouteFlagService,
    pub gateway: Gateway<UpstreamClient>,
    pub facts: Arc<dyn NodeFactsSource>,
    pub metrics: Arc<EdgeMetrics>,
}

pub type SharedState = Arc<ServerState>;
