use crate::settings::environment;

pub const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:9000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamOrigin {
    base: String,
}

impl Default for UpstreamOrigin {
    fn default() -> Self {
        UpstreamOrigin::new(DEFAULT_UPSTREAM)
    }
}

impl UpstreamOrigin {
    pub fn new(base: impl Into<String>) -> Self {
        let base = base.into();
        UpstreamOrigin {
            base: base.trim_end_matches('/').to_string(),
        }
    }

    pub fn from_environment() -> Self {
        UpstreamOrigin::new(environment::text_or(
            "VORTEX_UPSTREAM_URL",
            DEFAULT_UPSTREAM,
        ))
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn join(&self, path_and_query: &str) -> String {
        if path_and_query.starts_with('/') {
            format!("{}{}", self.base, path_and_query)
        } else {
            format!("{}/{}", self.base, path_and_query)
        }
    }

    pub fn websocket_base(&self) -> String {
        if let Some(rest) = self.base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.base.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UpstreamOrigin;

    #[test]
    fn a_trailing_slash_never_doubles_in_the_joined_path() {
        let origin = UpstreamOrigin::new("http://127.0.0.1:9000/");
        assert_eq!(origin.join("/health"), "http://127.0.0.1:9000/health");
        assert_eq!(origin.join("health"), "http://127.0.0.1:9000/health");
    }

    #[test]
    fn the_websocket_base_keeps_the_transport_security_of_the_origin() {
        assert_eq!(
            UpstreamOrigin::new("https://node:9000").websocket_base(),
            "wss://node:9000"
        );
        assert_eq!(
            UpstreamOrigin::new("http://node:9000").websocket_base(),
            "ws://node:9000"
        );
    }
}
