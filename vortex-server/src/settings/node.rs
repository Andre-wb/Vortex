use crate::settings::environment;

pub const VERSION: &str = "1.0.0";
pub const ENCRYPTION: &str = "AES-256-GCM";
pub const PASSWORD_HASH: &str = "Argon2id";
pub const AUTHENTICATION: &str = "JWT-HS256";
pub const FEDERATION: &str = "enabled";
pub const DEFAULT_NETWORK_MODE: &str = "local";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFacts {
    network_mode: String,
    ephemeral: bool,
    metadata_padding: bool,
}

impl Default for NodeFacts {
    fn default() -> Self {
        NodeFacts {
            network_mode: DEFAULT_NETWORK_MODE.to_string(),
            ephemeral: false,
            metadata_padding: true,
        }
    }
}

impl NodeFacts {
    pub fn new(network_mode: impl Into<String>, ephemeral: bool, metadata_padding: bool) -> Self {
        NodeFacts {
            network_mode: network_mode.into(),
            ephemeral,
            metadata_padding,
        }
    }

    pub fn from_environment() -> Self {
        NodeFacts::new(
            environment::text_or("NETWORK_MODE", DEFAULT_NETWORK_MODE),
            environment::flag("EPHEMERAL_MODE", false),
            environment::flag_strict("METADATA_PADDING", true),
        )
    }

    pub fn network_mode(&self) -> &str {
        &self.network_mode
    }

    pub fn ephemeral(&self) -> bool {
        self.ephemeral
    }

    pub fn metadata_padding(&self) -> bool {
        self.metadata_padding
    }

    pub fn global(&self) -> bool {
        self.network_mode == "global"
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeFacts, DEFAULT_NETWORK_MODE};

    #[test]
    fn the_default_node_is_local_padded_and_not_ephemeral() {
        let facts = NodeFacts::default();
        assert_eq!(facts.network_mode(), DEFAULT_NETWORK_MODE);
        assert!(!facts.ephemeral());
        assert!(facts.metadata_padding());
        assert!(!facts.global());
    }

    #[test]
    fn only_the_global_mode_adds_the_wide_area_fields() {
        assert!(NodeFacts::new("global", false, true).global());
        assert!(!NodeFacts::new("custom", false, true).global());
    }
}
