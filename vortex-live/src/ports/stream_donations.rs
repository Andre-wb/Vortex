use crate::error::Result;
use crate::stream::donation::Donation;
use vortex_core::room::room_id::RoomId;

pub trait StreamDonations: Send + Sync {
    fn add(&self, room: RoomId, donation: &Donation, until: f64, now: f64) -> Result<()>;

    fn list(&self, room: RoomId, now: f64) -> Result<Vec<Donation>>;

    fn clear(&self, room: RoomId, now: f64) -> Result<()>;

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool>;
}
