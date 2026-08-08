use crate::sw::config::{SwConfig, FALLBACK_TRANSPORT, VERSION};

#[derive(Debug, Clone, PartialEq)]
pub struct SwProfile {
    pub version: &'static str,
    pub transports: Vec<String>,
    pub primary_transport: String,
    pub cdn_relay_url: String,
    pub meek_url: String,
    pub cache_ttl_secs: u32,
    pub probe_interval_secs: u32,
    pub probe_interval_min_secs: u32,
    pub probe_interval_max_secs: u32,
    pub padding_enabled: bool,
    pub padding_buckets: Vec<u32>,
    pub padding_promote_probability: f64,
    pub padding_tile_step: u32,
    pub retry_max_attempts: u32,
    pub retry_backoff_base_ms: u32,
    pub retry_backoff_max_ms: u32,
}

pub fn of(
    config: &SwConfig,
    transports: &[String],
    cdn_relay_url: &str,
    meek_url: &str,
) -> SwProfile {
    SwProfile {
        version: VERSION,
        primary_transport: transports
            .first()
            .cloned()
            .unwrap_or_else(|| FALLBACK_TRANSPORT.to_owned()),
        transports: transports.to_vec(),
        cdn_relay_url: cdn_relay_url.to_owned(),
        meek_url: meek_url.to_owned(),
        cache_ttl_secs: config.cache_ttl_secs,
        probe_interval_secs: config.probe_interval_secs(),
        probe_interval_min_secs: config.probe_interval_min_secs(),
        probe_interval_max_secs: config.probe_interval_max_secs(),
        padding_enabled: config.padding.enabled,
        padding_buckets: config.padding.buckets(),
        padding_promote_probability: config.padding.promote_probability,
        padding_tile_step: config.padding.tile_step,
        retry_max_attempts: config.retry.max_attempts,
        retry_backoff_base_ms: config.retry.backoff_base_ms,
        retry_backoff_max_ms: config.retry.backoff_max_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::of;
    use crate::sw::config::SwConfig;

    fn named(items: &[&str]) -> Vec<String> {
        items.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn the_first_transport_offered_is_the_one_the_client_starts_with() {
        let profile = of(&SwConfig::default(), &named(&["websocket", "sse"]), "", "");
        assert_eq!(profile.primary_transport, "websocket");
        assert_eq!(profile.transports, named(&["websocket", "sse"]));
    }

    #[test]
    fn a_client_offered_nothing_is_told_to_go_direct() {
        let profile = of(&SwConfig::default(), &[], "", "");
        assert_eq!(profile.primary_transport, "direct");
        assert!(profile.transports.is_empty());
    }

    #[test]
    fn the_profile_carries_the_ladder_the_client_must_pad_to() {
        let profile = of(&SwConfig::default(), &named(&["sse"]), "", "");
        assert_eq!(profile.padding_buckets.first(), Some(&128));
        assert_eq!(profile.padding_buckets.last(), Some(&65536));
        assert_eq!(profile.padding_tile_step, 8192);
        assert!(profile.padding_enabled);
    }

    #[test]
    fn the_relay_addresses_are_carried_through_untouched() {
        let profile = of(
            &SwConfig::default(),
            &named(&["cdn_relay"]),
            "https://cdn.example.com",
            "https://meek.example.com",
        );
        assert_eq!(profile.cdn_relay_url, "https://cdn.example.com");
        assert_eq!(profile.meek_url, "https://meek.example.com");
    }

    #[test]
    fn the_profile_names_the_version_of_the_contract_it_speaks() {
        assert_eq!(of(&SwConfig::default(), &[], "", "").version, "4.0");
    }
}
