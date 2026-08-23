use std::collections::BTreeMap;

use crate::error::Result;
use vortex_core::room::room_id::RoomId;

pub trait StreamTally: Send + Sync {
    fn count_reaction(&self, room: RoomId, emoji: &str, until: f64, now: f64) -> Result<()>;

    fn reactions(&self, room: RoomId, now: f64) -> Result<BTreeMap<String, u64>>;

    fn raise_peak(&self, room: RoomId, seen: u64, until: f64, now: f64) -> Result<u64>;

    fn peak(&self, room: RoomId, now: f64) -> Result<u64>;

    fn clear(&self, room: RoomId, now: f64) -> Result<()>;

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool>;
}
