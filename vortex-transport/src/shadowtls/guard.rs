use crate::ports::random_source::RandomSource;
use crate::shadowtls::config::ShadowTlsConfig;
use crate::shadowtls::donor::allowlist::DonorAllowlist;
use crate::shadowtls::donor::target::DonorTarget;
use crate::shadowtls::relay::connection::Connection;
use crate::shadowtls::secret::keyring::Keyring;
use crate::shadowtls::session::keys;
use crate::shadowtls::session::role::Role;
use crate::shadowtls::session::stream::SealedStream;
use crate::shadowtls::switch::{sealer, session_id::SessionId};
use crate::tls::server_hello::ServerRandom;
use std::sync::Arc;

pub struct ShadowTls {
    keyring: Arc<Keyring>,
    allowlist: Arc<DonorAllowlist>,
    config: ShadowTlsConfig,
}

impl Default for ShadowTls {
    fn default() -> Self {
        ShadowTls::new(b"", b"")
    }
}

impl ShadowTls {
    pub fn new(password: &[u8], previous: &[u8]) -> Self {
        ShadowTls {
            keyring: Arc::new(Keyring::new(password, previous)),
            allowlist: Arc::new(DonorAllowlist::default()),
            config: ShadowTlsConfig::default(),
        }
    }

    pub fn with_donors(mut self, targets: Vec<DonorTarget>) -> Self {
        self.allowlist = Arc::new(DonorAllowlist::new(targets));
        self
    }

    pub fn with_config(mut self, config: ShadowTlsConfig) -> Self {
        self.config = config;
        self
    }

    pub fn is_configured(&self) -> bool {
        self.keyring.is_configured()
    }

    pub fn accepts_previous(&self) -> bool {
        self.keyring.accepts_previous()
    }

    pub fn donors(&self) -> &DonorAllowlist {
        &self.allowlist
    }

    pub fn config(&self) -> &ShadowTlsConfig {
        &self.config
    }

    pub fn connection(&self) -> Connection {
        Connection::new(self.keyring.clone(), self.allowlist.clone())
    }

    pub fn seal_switch(
        &self,
        server_random: &ServerRandom,
        session_id: &SessionId,
        random: &dyn RandomSource,
    ) -> Option<Vec<u8>> {
        let key = self.keyring.sealing_key()?;
        sealer::seal(key, server_random, session_id, &self.config, random)
    }

    pub fn seal_switch_with_padding(
        &self,
        server_random: &ServerRandom,
        session_id: &SessionId,
        padding: &[u8],
    ) -> Option<Vec<u8>> {
        let key = self.keyring.sealing_key()?;
        sealer::into_record(sealer::payload(key, server_random, session_id, padding))
    }

    pub fn stream(
        &self,
        server_random: &ServerRandom,
        session_id: &SessionId,
        role: Role,
    ) -> Option<SealedStream> {
        let key = self.keyring.sealing_key()?;
        Some(SealedStream::new(&keys::derive(
            key,
            server_random,
            session_id,
            role,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::ShadowTls;
    use crate::random::fixed_random::FixedRandom;
    use crate::shadowtls::donor::target::DonorTarget;
    use crate::shadowtls::session::role::Role;
    use crate::shadowtls::switch::session_id::SessionId;

    fn session_id() -> SessionId {
        SessionId::from_bytes([0x02; 16])
    }

    #[test]
    fn an_unconfigured_guard_can_neither_seal_nor_open() {
        let guard = ShadowTls::default();
        assert!(!guard.is_configured());
        let random = FixedRandom::new(vec![]).with_filler(0x00);
        assert!(guard
            .seal_switch(&[0x01; 32], &session_id(), &random)
            .is_none());
        assert!(guard
            .stream(&[0x01; 32], &session_id(), Role::Server)
            .is_none());
    }

    #[test]
    fn the_stream_it_hands_out_matches_the_other_side() {
        let guard = ShadowTls::new(b"testpass", b"");
        let mut server = guard
            .stream(&[0x01; 32], &session_id(), Role::Server)
            .unwrap();
        let mut client = guard
            .stream(&[0x01; 32], &session_id(), Role::Client)
            .unwrap();
        let frame = server.wrap(b"hello");
        assert_eq!(client.unwrap(&frame), Some(b"hello".to_vec()));
    }

    #[test]
    fn donors_can_be_replaced_wholesale() {
        let guard =
            ShadowTls::new(b"testpass", b"").with_donors(vec![DonorTarget::new("127.0.0.1", 9443)]);
        assert_eq!(guard.donors().targets().len(), 1);
        assert_eq!(guard.donors().fallback().port, 9443);
    }
}
