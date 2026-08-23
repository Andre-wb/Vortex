use crate::ports::peer_registry::PeerRegistry;
use crate::registry::address::PeerAddress;
use crate::registry::peer::PeerRecord;
use crate::registry::refusal::{RegistryError, Result};

pub struct UnavailablePeerRegistry;

impl UnavailablePeerRegistry {
    pub fn new() -> Self {
        UnavailablePeerRegistry
    }
}

impl Default for UnavailablePeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRegistry for UnavailablePeerRegistry {
    fn observe(&self, _record: &PeerRecord) -> Result<bool> {
        Err(RegistryError::Unavailable)
    }

    fn find(&self, _address: &PeerAddress) -> Result<Option<PeerRecord>> {
        Err(RegistryError::Unavailable)
    }

    fn alive(&self, _now: f64, _timeout: f64) -> Result<Vec<PeerRecord>> {
        Err(RegistryError::Unavailable)
    }

    fn forget_dead(&self, _now: f64, _timeout: f64) -> Result<usize> {
        Err(RegistryError::Unavailable)
    }

    fn set_rooms(&self, _address: &PeerAddress, _document: &str) -> Result<()> {
        Err(RegistryError::Unavailable)
    }

    fn rooms(&self, _address: &PeerAddress) -> Result<Option<String>> {
        Err(RegistryError::Unavailable)
    }

    fn count(&self) -> Result<usize> {
        Err(RegistryError::Unavailable)
    }
}
