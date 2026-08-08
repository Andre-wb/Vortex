use crate::latency::config::LatencyConfig;
use crate::sw::padding::PaddingLadder;
use crate::sw::retry::RetryPolicy;

pub const VERSION: &str = "4.0";
pub const DEFAULT_CACHE_TTL_SECS: u32 = 3600;
pub const FALLBACK_TRANSPORT: &str = "direct";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SwConfig {
    pub cache_ttl_secs: u32,
    pub padding: PaddingLadder,
    pub retry: RetryPolicy,
    pub schedule: LatencyConfig,
}

impl Default for SwConfig {
    fn default() -> Self {
        SwConfig {
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            padding: PaddingLadder::default(),
            retry: RetryPolicy::default(),
            schedule: LatencyConfig::default(),
        }
    }
}

impl SwConfig {
    pub fn probe_interval_secs(&self) -> u32 {
        self.schedule.probe_interval_secs.round() as u32
    }

    pub fn probe_interval_min_secs(&self) -> u32 {
        self.schedule.shortest_interval().round() as u32
    }

    pub fn probe_interval_max_secs(&self) -> u32 {
        self.schedule.longest_interval().round() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::SwConfig;

    #[test]
    fn the_client_is_told_the_same_schedule_the_server_keeps() {
        let config = SwConfig::default();
        assert_eq!(config.probe_interval_secs(), 60);
        assert_eq!(config.probe_interval_min_secs(), 30);
        assert_eq!(config.probe_interval_max_secs(), 108);
    }

    #[test]
    fn the_bounds_the_client_is_given_hold_the_interval_between_them() {
        let config = SwConfig::default();
        assert!(config.probe_interval_min_secs() < config.probe_interval_secs());
        assert!(config.probe_interval_max_secs() > config.probe_interval_secs());
    }
}
