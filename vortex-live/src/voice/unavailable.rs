use vortex_auth::account::user_id::UserId;

use crate::error::{Result, StateError};
use crate::ports::voice_presence::VoicePresence;
use crate::voice::joined::Joined;
use crate::voice::participant::Participant;
use crate::voice::patch::MutePatch;
use crate::voice::record::Presence;
use vortex_core::room::room_id::RoomId;

pub struct UnavailableVoicePresence;

impl Default for UnavailableVoicePresence {
    fn default() -> Self {
        UnavailableVoicePresence::new()
    }
}

impl UnavailableVoicePresence {
    pub fn new() -> Self {
        UnavailableVoicePresence
    }
}

impl VoicePresence for UnavailableVoicePresence {
    fn join(&self, _room: RoomId, _presence: &Presence, _now: f64) -> Result<Joined> {
        Err(StateError::Unavailable)
    }

    fn leave(&self, _room: RoomId, _user: UserId, _now: f64) -> Result<Option<Participant>> {
        Err(StateError::Unavailable)
    }

    fn list(&self, _room: RoomId, _now: f64) -> Result<Vec<Participant>> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _room: RoomId, _user: UserId, _now: f64) -> Result<Option<Participant>> {
        Err(StateError::Unavailable)
    }

    fn amend(
        &self,
        _room: RoomId,
        _user: UserId,
        _patch: MutePatch,
        _until: f64,
        _now: f64,
    ) -> Result<Option<Participant>> {
        Err(StateError::Unavailable)
    }

    fn renew(&self, _room: RoomId, _user: UserId, _until: f64, _now: f64) -> Result<bool> {
        Err(StateError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::UnavailableVoicePresence;
    use crate::error::StateError;
    use crate::ports::voice_presence::VoicePresence;
    use vortex_auth::account::user_id::UserId;
    use vortex_core::room::room_id::RoomId;

    fn room() -> RoomId {
        RoomId::of(1).unwrap()
    }

    #[test]
    fn a_channel_nobody_can_share_refuses_every_question_about_it() {
        let store = UnavailableVoicePresence::new();
        assert_eq!(store.list(room(), 1_000.0), Err(StateError::Unavailable));
        assert_eq!(
            store.find(room(), UserId::of(7).unwrap(), 1_000.0),
            Err(StateError::Unavailable)
        );
        assert_eq!(
            store.leave(room(), UserId::of(7).unwrap(), 1_000.0),
            Err(StateError::Unavailable)
        );
        assert_eq!(
            store.renew(room(), UserId::of(7).unwrap(), 1_120.0, 1_000.0),
            Err(StateError::Unavailable)
        );
    }
}
