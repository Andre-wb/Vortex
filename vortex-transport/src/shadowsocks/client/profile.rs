pub const PROTOCOL: &str = "vortex-shadowsocks";
pub const VERSION: u32 = 2;
pub const CIPHER: &str = "aes-256-gcm";
pub const KEY_DERIVATION: &str = "hkdf-sha256";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProfile {
    pub protocol: &'static str,
    pub version: u32,
    pub server: String,
    pub server_port: u16,
    pub cipher: &'static str,
    pub key_derivation: &'static str,
}

impl ClientProfile {
    pub fn new(server: &str, server_port: u16) -> Self {
        ClientProfile {
            protocol: PROTOCOL,
            version: VERSION,
            server: server.to_owned(),
            server_port,
            cipher: CIPHER,
            key_derivation: KEY_DERIVATION,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientProfile, CIPHER, KEY_DERIVATION, PROTOCOL, VERSION};

    #[test]
    fn the_profile_names_the_transport_and_its_cipher() {
        let profile = ClientProfile::new("vortex.example", 8443);
        assert_eq!(profile.protocol, PROTOCOL);
        assert_eq!(profile.version, VERSION);
        assert_eq!(profile.cipher, CIPHER);
        assert_eq!(profile.key_derivation, KEY_DERIVATION);
        assert_eq!(profile.server, "vortex.example");
        assert_eq!(profile.server_port, 8443);
    }

    #[test]
    fn the_profile_never_claims_to_be_the_published_shadowsocks() {
        let profile = ClientProfile::new("vortex.example", 8443);
        assert_ne!(profile.protocol, "shadowsocks");
        assert_ne!(profile.key_derivation, "evp_bytestokey");
        assert_ne!(profile.key_derivation, "hkdf-sha1");
    }

    #[test]
    fn the_profile_never_carries_the_password() {
        let shown = format!("{:?}", ClientProfile::new("vortex.example", 8443));
        assert!(!shown.contains("password"));
    }
}
