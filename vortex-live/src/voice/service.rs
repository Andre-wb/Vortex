use std::sync::Arc;

use vortex_auth::account::user_id::UserId;
use vortex_auth::ports::clock::Clock;

use crate::error::Result;
use crate::identity::person::Person;
use crate::ports::voice_presence::VoicePresence;
use crate::time::lifetime;
use crate::time::stamp;
use crate::voice::joined::Joined;
use crate::voice::participant::Participant;
use crate::voice::patch::MutePatch;
use crate::voice::record::Presence;
use vortex_core::room::room_id::RoomId;

pub struct VoiceChannelService {
    presence: Arc<dyn VoicePresence>,
    clock: Arc<dyn Clock>,
}

impl VoiceChannelService {
    pub fn new(presence: Arc<dyn VoicePresence>, clock: Arc<dyn Clock>) -> Self {
        VoiceChannelService { presence, clock }
    }

    pub fn join(&self, room: RoomId, person: &Person) -> Result<Joined> {
        let now = self.clock.unix_seconds();
        let participant = Participant {
            user_id: person.user_id,
            username: person.username.clone(),
            display_name: person.display_name.clone(),
            avatar_emoji: person.avatar_emoji.clone(),
            avatar_url: person.avatar_url.clone(),
            joined_at: stamp::written(now),
            is_muted: false,
            is_video: false,
        };
        self.presence.join(
            room,
            &Presence::new(participant, lifetime::presence().expires_at(now)),
            now,
        )
    }

    pub fn leave(&self, room: RoomId, user: UserId) -> Result<Option<Participant>> {
        self.presence.leave(room, user, self.clock.unix_seconds())
    }

    pub fn participants(&self, room: RoomId) -> Result<Vec<Participant>> {
        self.presence.list(room, self.clock.unix_seconds())
    }

    pub fn count(&self, room: RoomId) -> Result<usize> {
        Ok(self.participants(room)?.len())
    }

    pub fn find(&self, room: RoomId, user: UserId) -> Result<Option<Participant>> {
        self.presence.find(room, user, self.clock.unix_seconds())
    }

    pub fn amend(
        &self,
        room: RoomId,
        user: UserId,
        patch: MutePatch,
    ) -> Result<Option<Participant>> {
        let now = self.clock.unix_seconds();
        self.presence
            .amend(room, user, patch, lifetime::presence().expires_at(now), now)
    }

    pub fn renew(&self, room: RoomId, user: UserId) -> Result<bool> {
        let now = self.clock.unix_seconds();
        self.presence
            .renew(room, user, lifetime::presence().expires_at(now), now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::VoiceChannelService;
    use crate::error::StateError;
    use crate::identity::person::Person;
    use crate::voice::memory::MemoryVoicePresence;
    use crate::voice::patch::MutePatch;
    use crate::voice::unavailable::UnavailableVoicePresence;
    use vortex_auth::account::user_id::UserId;
    use vortex_auth::time::manual_clock::ManualClock;
    use vortex_core::room::room_id::RoomId;

    fn room() -> RoomId {
        RoomId::of(1).unwrap()
    }

    fn ann() -> Person {
        Person::of(7, "ann", Some("Ann"), None, None)
    }

    fn bob() -> Person {
        Person::of(8, "bob", None, None, None)
    }

    fn service(clock: Arc<ManualClock>) -> VoiceChannelService {
        VoiceChannelService::new(Arc::new(MemoryVoicePresence::new()), clock)
    }

    #[test]
    fn joining_a_channel_puts_the_participant_where_every_worker_sees_them() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let joined = service.join(room(), &ann()).unwrap();

        assert!(!joined.already_in());
        assert_eq!(joined.participant().display_name, "Ann");
        assert_eq!(joined.participant().joined_at, "1970-01-01T00:16:40+00:00");
        assert_eq!(service.count(room()).unwrap(), 1);
    }

    #[test]
    fn joining_twice_does_not_double_the_participant() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        service.join(room(), &ann()).unwrap();
        assert!(service.join(room(), &ann()).unwrap().already_in());
        assert_eq!(service.count(room()).unwrap(), 1);
    }

    #[test]
    fn the_channel_lists_participants_in_the_order_they_joined() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        service.join(room(), &bob()).unwrap();
        clock.advance(1.0);
        service.join(room(), &ann()).unwrap();

        let listed = service.participants(room()).unwrap();
        assert_eq!(listed[0].user_id, 8);
        assert_eq!(listed[1].user_id, 7);
    }

    #[test]
    fn leaving_gives_back_who_left_and_only_once() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        service.join(room(), &ann()).unwrap();

        assert_eq!(
            service
                .leave(room(), UserId::of(7).unwrap())
                .unwrap()
                .unwrap()
                .user_id,
            7
        );
        assert!(service
            .leave(room(), UserId::of(7).unwrap())
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_participant_without_a_mute_flag_is_flipped() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        service.join(room(), &ann()).unwrap();

        let amended = service
            .amend(room(), UserId::of(7).unwrap(), MutePatch::new(None, None))
            .unwrap()
            .unwrap();
        assert!(amended.is_muted);
        assert!(!amended.is_video);
    }

    #[test]
    fn nobody_who_is_not_in_the_channel_is_amended() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        assert!(service
            .amend(room(), UserId::of(7).unwrap(), MutePatch::default())
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_participant_nobody_renews_drops_off_the_list() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        service.join(room(), &ann()).unwrap();

        clock.advance(120.0);
        assert_eq!(service.count(room()).unwrap(), 0);
    }

    #[test]
    fn renewing_keeps_a_silent_participant_in_the_channel() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        service.join(room(), &ann()).unwrap();

        clock.advance(90.0);
        assert!(service.renew(room(), UserId::of(7).unwrap()).unwrap());
        clock.advance(90.0);
        assert_eq!(service.count(room()).unwrap(), 1);
    }

    #[test]
    fn renewing_a_participant_who_already_dropped_off_puts_nobody_back() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        service.join(room(), &ann()).unwrap();

        clock.advance(120.0);
        assert!(!service.renew(room(), UserId::of(7).unwrap()).unwrap());
    }

    #[test]
    fn without_shared_state_the_channel_refuses_instead_of_answering_for_one_worker() {
        let service = VoiceChannelService::new(
            Arc::new(UnavailableVoicePresence::new()),
            Arc::new(ManualClock::at(1_000.0)),
        );
        assert_eq!(service.join(room(), &ann()), Err(StateError::Unavailable));
        assert_eq!(service.participants(room()), Err(StateError::Unavailable));
    }
}
