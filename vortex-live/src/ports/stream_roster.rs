use vortex_auth::account::user_id::UserId;

use crate::error::Result;
use crate::store::swapped::Swapped;
use crate::stream::participant::StreamParticipant;
use vortex_core::room::room_id::RoomId;

pub trait StreamRoster: Send + Sync {
    fn seat(
        &self,
        room: RoomId,
        participant: &StreamParticipant,
        until: f64,
        now: f64,
    ) -> Result<Option<StreamParticipant>>;

    fn find(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<StreamParticipant>>;

    fn list(&self, room: RoomId, now: f64) -> Result<Vec<StreamParticipant>>;

    fn swap_member(
        &self,
        room: RoomId,
        user: UserId,
        expected: &StreamParticipant,
        replacement: &StreamParticipant,
        until: f64,
        now: f64,
    ) -> Result<Swapped>;

    fn unseat(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<StreamParticipant>>;

    fn clear(&self, room: RoomId, now: f64) -> Result<()>;

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool>;
}
