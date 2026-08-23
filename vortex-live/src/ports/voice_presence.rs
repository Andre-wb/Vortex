use vortex_auth::account::user_id::UserId;

use crate::error::Result;
use crate::voice::joined::Joined;
use crate::voice::participant::Participant;
use crate::voice::patch::MutePatch;
use crate::voice::record::Presence;
use vortex_core::room::room_id::RoomId;

pub trait VoicePresence: Send + Sync {
    fn join(&self, room: RoomId, presence: &Presence, now: f64) -> Result<Joined>;

    fn leave(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<Participant>>;

    fn list(&self, room: RoomId, now: f64) -> Result<Vec<Participant>>;

    fn find(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<Participant>>;

    fn amend(
        &self,
        room: RoomId,
        user: UserId,
        patch: MutePatch,
        until: f64,
        now: f64,
    ) -> Result<Option<Participant>>;

    fn renew(&self, room: RoomId, user: UserId, until: f64, now: f64) -> Result<bool>;
}
