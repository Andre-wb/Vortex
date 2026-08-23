use crate::registry::address::PeerAddress;
use crate::registry::peer::PeerRecord;
use crate::registry::refusal::Result;

pub trait PeerRegistry: Send + Sync {
    fn observe(&self, record: &PeerRecord) -> Result<bool>;

    fn find(&self, address: &PeerAddress) -> Result<Option<PeerRecord>>;

    fn alive(&self, now: f64, timeout: f64) -> Result<Vec<PeerRecord>>;

    fn forget_dead(&self, now: f64, timeout: f64) -> Result<usize>;

    fn set_rooms(&self, address: &PeerAddress, document: &str) -> Result<()>;

    fn rooms(&self, address: &PeerAddress) -> Result<Option<String>>;

    fn count(&self) -> Result<usize>;
}
