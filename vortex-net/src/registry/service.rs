use std::sync::Arc;

use crate::ports::peer_registry::PeerRegistry;
use crate::registry::address::PeerAddress;
use crate::registry::limits;
use crate::registry::name::PeerName;
use crate::registry::peer::PeerRecord;
use crate::registry::pubkey::NodePubkey;
use crate::registry::refusal::{PeerRefusal, Result};

pub struct PeerRegistryService {
    peers: Arc<dyn PeerRegistry>,
    timeout: f64,
}

impl PeerRegistryService {
    pub fn new(peers: Arc<dyn PeerRegistry>, timeout: f64) -> Self {
        PeerRegistryService { peers, timeout }
    }

    pub fn timeout(&self) -> f64 {
        self.timeout
    }

    pub fn store(&self) -> Arc<dyn PeerRegistry> {
        self.peers.clone()
    }

    pub fn heard(
        &self,
        address: &str,
        name: &str,
        port: u16,
        pubkey: Option<&str>,
        now: f64,
    ) -> std::result::Result<Result<bool>, PeerRefusal> {
        let named = PeerAddress::parse(address)?;
        let called = PeerName::parse(name)?;
        if port == 0 {
            return Err(PeerRefusal::PortOutsideRange);
        }
        let key = pubkey.and_then(NodePubkey::parse);
        let record = PeerRecord::seen(named, called, port, key, now);
        Ok(self.peers.observe(&record))
    }

    pub fn find(
        &self,
        address: &str,
    ) -> std::result::Result<Result<Option<PeerRecord>>, PeerRefusal> {
        let named = PeerAddress::parse(address)?;
        Ok(self.peers.find(&named))
    }

    pub fn alive(&self, now: f64) -> Result<Vec<PeerRecord>> {
        self.peers.alive(now, self.timeout)
    }

    pub fn forget_dead(&self, now: f64) -> Result<usize> {
        self.peers.forget_dead(now, self.timeout)
    }

    pub fn set_rooms(
        &self,
        address: &str,
        document: &str,
    ) -> std::result::Result<Result<()>, PeerRefusal> {
        let named = PeerAddress::parse(address)?;
        if document.len() > limits::MAX_ROOMS_DOCUMENT {
            return Err(PeerRefusal::OverLongRoomsDocument);
        }
        Ok(self.peers.set_rooms(&named, document))
    }

    pub fn rooms_of_the_living(&self, now: f64) -> Result<Vec<(PeerRecord, String)>> {
        let living = self.peers.alive(now, self.timeout)?;
        let mut told = Vec::new();
        for known in living {
            if let Some(document) = self.peers.rooms(known.address())? {
                told.push((known, document));
            }
        }
        Ok(told)
    }

    pub fn count(&self) -> Result<usize> {
        self.peers.count()
    }
}
