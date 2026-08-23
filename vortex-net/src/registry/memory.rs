use std::collections::HashMap;

use parking_lot::Mutex;

use crate::ports::peer_registry::PeerRegistry;
use crate::registry::address::PeerAddress;
use crate::registry::peer::PeerRecord;
use crate::registry::refusal::Result;

#[derive(Default)]
struct Shelf {
    peers: HashMap<String, PeerRecord>,
    rooms: HashMap<String, String>,
}

pub struct MemoryPeerRegistry {
    shelf: Mutex<Shelf>,
}

impl MemoryPeerRegistry {
    pub fn new() -> Self {
        MemoryPeerRegistry {
            shelf: Mutex::new(Shelf::default()),
        }
    }
}

impl Default for MemoryPeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRegistry for MemoryPeerRegistry {
    fn observe(&self, record: &PeerRecord) -> Result<bool> {
        let mut shelf = self.shelf.lock();
        let named = record.address().written().to_owned();
        match shelf.peers.get(&named) {
            Some(known) => {
                let refreshed = known.refreshed(
                    record.name().clone(),
                    record.port(),
                    record.pubkey().cloned(),
                    record.last_seen(),
                );
                shelf.peers.insert(named, refreshed);
                Ok(false)
            }
            None => {
                shelf.peers.insert(named, record.clone());
                Ok(true)
            }
        }
    }

    fn find(&self, address: &PeerAddress) -> Result<Option<PeerRecord>> {
        Ok(self.shelf.lock().peers.get(address.written()).cloned())
    }

    fn alive(&self, now: f64, timeout: f64) -> Result<Vec<PeerRecord>> {
        let shelf = self.shelf.lock();
        let mut held: Vec<PeerRecord> = shelf
            .peers
            .values()
            .filter(|known| known.alive(now, timeout))
            .cloned()
            .collect();
        held.sort_by(|left, right| left.address().cmp(right.address()));
        Ok(held)
    }

    fn forget_dead(&self, now: f64, timeout: f64) -> Result<usize> {
        let mut shelf = self.shelf.lock();
        let dead: Vec<String> = shelf
            .peers
            .values()
            .filter(|known| !known.alive(now, timeout))
            .map(|known| known.address().written().to_owned())
            .collect();
        for named in &dead {
            shelf.peers.remove(named);
            shelf.rooms.remove(named);
        }
        Ok(dead.len())
    }

    fn set_rooms(&self, address: &PeerAddress, document: &str) -> Result<()> {
        self.shelf
            .lock()
            .rooms
            .insert(address.written().to_owned(), document.to_owned());
        Ok(())
    }

    fn rooms(&self, address: &PeerAddress) -> Result<Option<String>> {
        Ok(self.shelf.lock().rooms.get(address.written()).cloned())
    }

    fn count(&self) -> Result<usize> {
        Ok(self.shelf.lock().peers.len())
    }
}
