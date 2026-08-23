use vortex_redis::config::RedisConfig;

use crate::settings::backbone;
use crate::settings::listen::ListenAddress;
use crate::settings::metrics::MetricsToken;
use crate::settings::node::NodeFacts;
use crate::settings::paths::NodePaths;
use crate::settings::stealth::StealthSettings;
use crate::settings::upstream::UpstreamOrigin;

#[derive(Debug, Clone, Default)]
pub struct ServerSettings {
    pub listen: ListenAddress,
    pub upstream: UpstreamOrigin,
    pub node: NodeFacts,
    pub paths: NodePaths,
    pub stealth: StealthSettings,
    pub metrics_token: MetricsToken,
    pub backbone: RedisConfig,
}

impl ServerSettings {
    pub fn from_environment() -> Self {
        ServerSettings {
            listen: ListenAddress::from_environment(),
            upstream: UpstreamOrigin::from_environment(),
            node: NodeFacts::from_environment(),
            paths: NodePaths::from_environment(),
            stealth: StealthSettings::from_environment(),
            metrics_token: MetricsToken::from_environment(),
            backbone: backbone::from_environment(),
        }
    }
}
