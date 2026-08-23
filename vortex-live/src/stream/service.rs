use std::sync::Arc;

use vortex_auth::account::user_id::UserId;
use vortex_auth::ports::clock::Clock;

use crate::error::{Result, StateError};
use crate::identity::person::Person;
use crate::ports::stream_donations::StreamDonations;
use crate::ports::stream_hands::StreamHands;
use crate::ports::stream_records::StreamRecords;
use crate::ports::stream_roster::StreamRoster;
use crate::ports::stream_tally::StreamTally;
use crate::store::swapped::ATTEMPTS;
use crate::stream::donation::Donation;
use crate::stream::outcome::{
    Amended, Donated, Granted, Hand, Kicked, Opened, Reacted, Seated, Stopped, Unseated, Updated,
};
use crate::stream::participant::StreamParticipant;
use crate::stream::record::{Opening, Stream};
use crate::stream::role::StreamRole;
use crate::stream::settings::StreamPatch;
use crate::stream::view::Snapshot;
use crate::time::{lifetime, stamp};
use vortex_core::room::room_id::RoomId;

pub const MAX_EMOJI_CHARS: usize = 10;

pub struct Grant {
    pub role: Option<StreamRole>,
    pub can_speak: Option<bool>,
    pub can_video: Option<bool>,
    pub can_screen_share: Option<bool>,
}

pub struct StreamService {
    records: Arc<dyn StreamRecords>,
    roster: Arc<dyn StreamRoster>,
    hands: Arc<dyn StreamHands>,
    tally: Arc<dyn StreamTally>,
    donations: Arc<dyn StreamDonations>,
    clock: Arc<dyn Clock>,
}

impl StreamService {
    pub fn new(
        records: Arc<dyn StreamRecords>,
        roster: Arc<dyn StreamRoster>,
        hands: Arc<dyn StreamHands>,
        tally: Arc<dyn StreamTally>,
        donations: Arc<dyn StreamDonations>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        StreamService {
            records,
            roster,
            hands,
            tally,
            donations,
            clock,
        }
    }

    pub fn open(&self, room: RoomId, host: Person, opening: Opening) -> Result<Opened> {
        let now = self.clock.unix_seconds();
        let until = lifetime::presence().expires_at(now);
        let stream = Stream::opened(
            room.value(),
            host.user_id,
            opening,
            stamp::written(now),
            until,
        );
        if !self.records.open(room, &stream, now)? {
            return Ok(Opened::AlreadyLive);
        }

        self.wipe(room, now)?;
        let seat = StreamParticipant::joining(host, StreamRole::Host, stamp::written(now));
        self.roster.seat(room, &seat, until, now)?;
        self.tally.raise_peak(room, 1, until, now)?;
        Ok(Opened::Fresh(Box::new(self.snapshot(room, stream, now)?)))
    }

    pub fn stop(&self, room: RoomId) -> Result<Stopped> {
        let now = self.clock.unix_seconds();
        if self.records.find(room, now)?.is_none() {
            return Ok(Stopped::Missing);
        }
        let peak = self.tally.peak(room, now)?;
        self.records.forget(room, now)?;
        self.wipe(room, now)?;
        Ok(Stopped::Stopped { peak })
    }

    pub fn join(&self, room: RoomId, person: Person, runs_the_room: bool) -> Result<Seated> {
        let now = self.clock.unix_seconds();
        let Some(stream) = self.records.find(room, now)? else {
            return Ok(Seated::Missing);
        };
        let until = lifetime::presence().expires_at(now);
        let role = if runs_the_room {
            StreamRole::CoHost
        } else {
            StreamRole::Viewer
        };
        let seat = StreamParticipant::joining(person, role, stamp::written(now));

        if self.roster.seat(room, &seat, until, now)?.is_some() {
            return Ok(Seated::Already(Box::new(self.snapshot(room, stream, now)?)));
        }
        let watching = self.roster.list(room, now)?.len() as u64;
        self.tally.raise_peak(room, watching, until, now)?;
        Ok(Seated::Fresh(Box::new(self.snapshot(room, stream, now)?)))
    }

    pub fn leave(&self, room: RoomId, user: UserId) -> Result<Unseated> {
        let now = self.clock.unix_seconds();
        let Some(stream) = self.records.find(room, now)? else {
            return Ok(Unseated::Missing);
        };
        if self.roster.unseat(room, user, now)?.is_none() {
            return Ok(Unseated::NotIn);
        }
        self.hands.lower(room, user, now)?;

        let host_left = stream.host_id == user.value();
        if host_left {
            self.records.forget(room, now)?;
            self.wipe(room, now)?;
        }
        Ok(Unseated::Left { host_left })
    }

    pub fn raise_hand(&self, room: RoomId, user: UserId) -> Result<Hand> {
        let now = self.clock.unix_seconds();
        let Some(stream) = self.records.find(room, now)? else {
            return Ok(Hand::Missing);
        };
        let Some(held) = self.roster.find(room, user, now)? else {
            return Ok(Hand::NotIn);
        };
        if held.role.runs_the_stream() {
            return Ok(Hand::AlreadySpeaks);
        }

        if stream.auto_accept_speakers {
            let promoted = self.amend_member(room, user, |held| held.promoted_to_speaker())?;
            self.hands.lower(room, user, now)?;
            return Ok(match promoted {
                Some(promoted) => Hand::AutoAccepted(Box::new(promoted)),
                None => Hand::NotIn,
            });
        }

        if self
            .amend_member(room, user, |held| held.with_hand(true))?
            .is_none()
        {
            return Ok(Hand::NotIn);
        }
        self.hands
            .raise(room, user, now, lifetime::presence().expires_at(now), now)?;
        Ok(Hand::Raised)
    }

    pub fn lower_hand(&self, room: RoomId, user: UserId) -> Result<Hand> {
        let now = self.clock.unix_seconds();
        if self.records.find(room, now)?.is_none() {
            return Ok(Hand::Missing);
        }
        if self
            .amend_member(room, user, |held| held.with_hand(false))?
            .is_none()
        {
            return Ok(Hand::NotIn);
        }
        self.hands.lower(room, user, now)?;
        Ok(Hand::Lowered)
    }

    pub fn grant(
        &self,
        room: RoomId,
        actor: UserId,
        target: UserId,
        grant: Grant,
    ) -> Result<Granted> {
        let now = self.clock.unix_seconds();
        let Some(stream) = self.records.find(room, now)? else {
            return Ok(Granted::Missing);
        };
        if !self.runs(room, actor, now)? {
            return Ok(Granted::NotAllowed);
        }
        let Some(held) = self.roster.find(room, target, now)? else {
            return Ok(Granted::NoSuchParticipant);
        };
        if held.role == StreamRole::Host && actor.value() != stream.host_id {
            return Ok(Granted::NotAllowed);
        }

        let granted = self.amend_member(room, target, |held| {
            let mut changed = match grant.role {
                Some(role) => held.in_role(role),
                None => held.clone(),
            };
            changed = changed.granted(changed.allowed.granting(
                grant.can_speak,
                grant.can_video,
                grant.can_screen_share,
            ));
            if changed.allowed.can_speak && changed.hand_raised {
                changed = changed.with_hand(false);
            }
            changed
        })?;

        match granted {
            Some(granted) => {
                if granted.allowed.can_speak {
                    self.hands.lower(room, target, now)?;
                }
                Ok(Granted::Granted(Box::new(granted)))
            }
            None => Ok(Granted::NoSuchParticipant),
        }
    }

    pub fn kick(&self, room: RoomId, actor: UserId, target: UserId) -> Result<Kicked> {
        let now = self.clock.unix_seconds();
        let Some(stream) = self.records.find(room, now)? else {
            return Ok(Kicked::Missing);
        };
        if !self.runs(room, actor, now)? {
            return Ok(Kicked::NotAllowed);
        }
        if target.value() == stream.host_id {
            return Ok(Kicked::CannotKickHost);
        }
        if self.roster.unseat(room, target, now)?.is_none() {
            return Ok(Kicked::NoSuchParticipant);
        }
        self.hands.lower(room, target, now)?;
        Ok(Kicked::Kicked)
    }

    pub fn react(&self, room: RoomId, user: UserId, emoji: &str) -> Result<Reacted> {
        let now = self.clock.unix_seconds();
        let Some(stream) = self.records.find(room, now)? else {
            return Ok(Reacted::Missing);
        };
        if !stream.allow_reactions {
            return Ok(Reacted::Disabled);
        }
        if self.roster.find(room, user, now)?.is_none() {
            return Ok(Reacted::NotIn);
        }
        let counted = trimmed(emoji);
        self.tally
            .count_reaction(room, &counted, lifetime::presence().expires_at(now), now)?;
        Ok(Reacted::Counted(counted))
    }

    pub fn donate(
        &self,
        room: RoomId,
        user: UserId,
        amount: &str,
        currency: &str,
        message: &str,
    ) -> Result<Donated> {
        let now = self.clock.unix_seconds();
        let Some(stream) = self.records.find(room, now)? else {
            return Ok(Donated::Missing);
        };
        if !stream.allow_donations {
            return Ok(Donated::Disabled);
        }
        let Some(held) = self.roster.find(room, user, now)? else {
            return Ok(Donated::NotIn);
        };
        let donation = Donation::from(&held.person, amount, currency, message, stamp::written(now));
        self.donations
            .add(room, &donation, lifetime::presence().expires_at(now), now)?;
        Ok(Donated::Donated(Box::new(donation)))
    }

    pub fn update(&self, room: RoomId, actor: UserId, patch: &StreamPatch) -> Result<Updated> {
        let now = self.clock.unix_seconds();
        if self.records.find(room, now)?.is_none() {
            return Ok(Updated::Missing);
        }
        if !self.runs(room, actor, now)? {
            return Ok(Updated::NotAllowed);
        }

        for _ in 0..ATTEMPTS {
            let now = self.clock.unix_seconds();
            let Some(held) = self.records.find(room, now)? else {
                return Ok(Updated::Missing);
            };
            let replacement = patch.applied(&held, lifetime::presence().expires_at(now));
            if self.records.swap(room, &held, &replacement, now)?.done() {
                return Ok(Updated::Updated(Box::new(self.snapshot(
                    room,
                    replacement,
                    now,
                )?)));
            }
        }
        Err(StateError::Unavailable)
    }

    pub fn mute(
        &self,
        room: RoomId,
        user: UserId,
        is_muted: Option<bool>,
        is_video_on: Option<bool>,
    ) -> Result<Amended> {
        let now = self.clock.unix_seconds();
        if self.records.find(room, now)?.is_none() {
            return Ok(Amended::Missing);
        }
        Ok(
            match self.amend_member(room, user, |held| held.muted(is_muted, is_video_on))? {
                Some(amended) => Amended::Amended(Box::new(amended)),
                None => Amended::Missing,
            },
        )
    }

    pub fn share_screen(&self, room: RoomId, user: UserId, sharing: bool) -> Result<Amended> {
        let now = self.clock.unix_seconds();
        if self.records.find(room, now)?.is_none() {
            return Ok(Amended::Missing);
        }
        let Some(held) = self.roster.find(room, user, now)? else {
            return Ok(Amended::Missing);
        };
        if !held.allowed.can_screen_share {
            return Ok(Amended::NotAllowed);
        }
        Ok(
            match self.amend_member(room, user, |held| held.sharing(sharing))? {
                Some(amended) => Amended::Amended(Box::new(amended)),
                None => Amended::Missing,
            },
        )
    }

    pub fn status(&self, room: RoomId) -> Result<Option<Snapshot>> {
        let now = self.clock.unix_seconds();
        let Some(stream) = self.records.find(room, now)? else {
            return Ok(None);
        };
        Ok(Some(self.snapshot(room, stream, now)?))
    }

    pub fn donations(&self, room: RoomId) -> Result<Vec<Donation>> {
        self.donations.list(room, self.clock.unix_seconds())
    }

    pub fn renew(&self, room: RoomId) -> Result<bool> {
        let now = self.clock.unix_seconds();
        let until = lifetime::presence().expires_at(now);
        let mut renewed = false;
        for _ in 0..ATTEMPTS {
            let Some(held) = self.records.find(room, now)? else {
                return Ok(false);
            };
            if self
                .records
                .swap(room, &held, &held.renewed(until), now)?
                .done()
            {
                renewed = true;
                break;
            }
        }
        if !renewed {
            return Err(StateError::Unavailable);
        }
        self.roster.renew(room, until, now)?;
        self.hands.renew(room, until, now)?;
        self.tally.renew(room, until, now)?;
        self.donations.renew(room, until, now)?;
        Ok(true)
    }

    fn runs(&self, room: RoomId, actor: UserId, now: f64) -> Result<bool> {
        Ok(self
            .roster
            .find(room, actor, now)?
            .is_some_and(|held| held.role.runs_the_stream()))
    }

    fn snapshot(&self, room: RoomId, stream: Stream, now: f64) -> Result<Snapshot> {
        Ok(Snapshot {
            stream,
            participants: self.roster.list(room, now)?,
            hands: self.hands.queue(room, now)?,
            reactions: self.tally.reactions(room, now)?,
            peak: self.tally.peak(room, now)?,
        })
    }

    fn wipe(&self, room: RoomId, now: f64) -> Result<()> {
        self.roster.clear(room, now)?;
        self.hands.clear(room, now)?;
        self.tally.clear(room, now)?;
        self.donations.clear(room, now)?;
        Ok(())
    }

    fn amend_member(
        &self,
        room: RoomId,
        user: UserId,
        mut change: impl FnMut(&StreamParticipant) -> StreamParticipant,
    ) -> Result<Option<StreamParticipant>> {
        for _ in 0..ATTEMPTS {
            let now = self.clock.unix_seconds();
            let Some(held) = self.roster.find(room, user, now)? else {
                return Ok(None);
            };
            let replacement = change(&held);
            if self
                .roster
                .swap_member(
                    room,
                    user,
                    &held,
                    &replacement,
                    lifetime::presence().expires_at(now),
                    now,
                )?
                .done()
            {
                return Ok(Some(replacement));
            }
        }
        Err(StateError::Unavailable)
    }
}

fn trimmed(emoji: &str) -> String {
    emoji.chars().take(MAX_EMOJI_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{Grant, StreamService};
    use crate::error::StateError;
    use crate::identity::person::Person;
    use crate::stream::memory::{
        MemoryStreamDonations, MemoryStreamHands, MemoryStreamRecords, MemoryStreamRoster,
        MemoryStreamTally,
    };
    use crate::stream::outcome::{
        Amended, Donated, Granted, Hand, Kicked, Opened, Reacted, Seated, Stopped, Unseated,
        Updated,
    };
    use crate::stream::record::tests::opening;
    use crate::stream::record::Opening;
    use crate::stream::role::StreamRole;
    use crate::stream::settings::StreamPatch;
    use crate::stream::unavailable::UnavailableStreamRecords;
    use crate::stream::view::Snapshot;
    use vortex_auth::account::user_id::UserId;
    use vortex_auth::time::manual_clock::ManualClock;
    use vortex_core::room::room_id::RoomId;

    fn room() -> RoomId {
        RoomId::of(1).unwrap()
    }

    fn ann() -> UserId {
        UserId::of(7).unwrap()
    }

    fn bob() -> UserId {
        UserId::of(8).unwrap()
    }

    fn host() -> Person {
        Person::of(7, "ann", Some("Ann"), None, None)
    }

    fn viewer() -> Person {
        Person::of(8, "bob", None, None, None)
    }

    fn service(clock: Arc<ManualClock>) -> StreamService {
        StreamService::new(
            Arc::new(MemoryStreamRecords::new()),
            Arc::new(MemoryStreamRoster::new()),
            Arc::new(MemoryStreamHands::new()),
            Arc::new(MemoryStreamTally::new()),
            Arc::new(MemoryStreamDonations::new()),
            clock,
        )
    }

    fn live(service: &StreamService) -> Snapshot {
        match service.open(room(), host(), opening()).unwrap() {
            Opened::Fresh(snapshot) => *snapshot,
            Opened::AlreadyLive => panic!("первая трансляция в канале не должна быть повтором"),
        }
    }

    fn watching(service: &StreamService) {
        assert!(matches!(
            service.join(room(), viewer(), false).unwrap(),
            Seated::Fresh(_)
        ));
    }

    #[test]
    fn opening_a_stream_seats_the_host_and_starts_the_count() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let snapshot = live(&service);

        assert_eq!(snapshot.stream.host_id, 7);
        assert_eq!(snapshot.viewer_count(), 1);
        assert_eq!(snapshot.peak, 1);
        assert_eq!(snapshot.participants[0].role, StreamRole::Host);
    }

    #[test]
    fn a_channel_that_is_already_live_does_not_open_a_second_stream() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        assert_eq!(
            service.open(room(), host(), opening()).unwrap(),
            Opened::AlreadyLive
        );
    }

    #[test]
    fn a_viewer_joins_muted_and_is_counted_by_every_worker() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);

        let snapshot = service.status(room()).unwrap().unwrap();
        assert_eq!(snapshot.viewer_count(), 2);
        assert_eq!(snapshot.peak, 2);
        let seated = snapshot
            .participants
            .iter()
            .find(|participant| participant.person.user_id == 8)
            .unwrap();
        assert_eq!(seated.role, StreamRole::Viewer);
        assert!(seated.is_muted);
    }

    #[test]
    fn a_room_admin_joins_the_stream_as_a_co_host() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        assert!(matches!(
            service.join(room(), viewer(), true).unwrap(),
            Seated::Fresh(_)
        ));

        let seated = service.status(room()).unwrap().unwrap();
        let admin = seated
            .participants
            .iter()
            .find(|participant| participant.person.user_id == 8)
            .unwrap();
        assert_eq!(admin.role, StreamRole::CoHost);
    }

    #[test]
    fn joining_twice_seats_the_viewer_once() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);

        assert!(matches!(
            service.join(room(), viewer(), false).unwrap(),
            Seated::Already(_)
        ));
        assert_eq!(service.status(room()).unwrap().unwrap().viewer_count(), 2);
    }

    #[test]
    fn the_peak_remembers_the_largest_audience_the_stream_ever_had() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);
        service.leave(room(), bob()).unwrap();

        let snapshot = service.status(room()).unwrap().unwrap();
        assert_eq!(snapshot.viewer_count(), 1);
        assert_eq!(snapshot.peak, 2);
    }

    #[test]
    fn a_stream_nobody_opened_is_missing_everywhere() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        assert_eq!(
            service.join(room(), viewer(), false).unwrap(),
            Seated::Missing
        );
        assert_eq!(service.leave(room(), ann()).unwrap(), Unseated::Missing);
        assert_eq!(service.raise_hand(room(), ann()).unwrap(), Hand::Missing);
        assert_eq!(
            service.react(room(), ann(), "\u{2764}").unwrap(),
            Reacted::Missing
        );
        assert_eq!(service.stop(room()).unwrap(), Stopped::Missing);
        assert!(service.status(room()).unwrap().is_none());
    }

    #[test]
    fn whoever_is_not_watching_does_not_leave_the_stream() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        assert_eq!(service.leave(room(), bob()).unwrap(), Unseated::NotIn);
    }

    #[test]
    fn the_host_leaving_ends_the_stream_for_everyone() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);

        assert_eq!(
            service.leave(room(), ann()).unwrap(),
            Unseated::Left { host_left: true }
        );
        assert!(service.status(room()).unwrap().is_none());
    }

    #[test]
    fn stopping_the_stream_reports_the_peak_and_clears_everything() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);

        assert_eq!(service.stop(room()).unwrap(), Stopped::Stopped { peak: 2 });
        assert!(service.status(room()).unwrap().is_none());
        assert_eq!(service.stop(room()).unwrap(), Stopped::Missing);
    }

    #[test]
    fn a_raised_hand_stands_in_a_queue_every_worker_reads() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);

        assert_eq!(service.raise_hand(room(), bob()).unwrap(), Hand::Raised);
        let snapshot = service.status(room()).unwrap().unwrap();
        assert_eq!(snapshot.hands, vec![8]);
        assert!(
            snapshot
                .participants
                .iter()
                .find(|participant| participant.person.user_id == 8)
                .unwrap()
                .hand_raised
        );
    }

    #[test]
    fn whoever_already_speaks_does_not_raise_a_hand() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        assert_eq!(
            service.raise_hand(room(), ann()).unwrap(),
            Hand::AlreadySpeaks
        );
    }

    #[test]
    fn a_lowered_hand_leaves_the_queue() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);
        service.raise_hand(room(), bob()).unwrap();

        assert_eq!(service.lower_hand(room(), bob()).unwrap(), Hand::Lowered);
        assert!(service.status(room()).unwrap().unwrap().hands.is_empty());
    }

    #[test]
    fn a_stream_that_accepts_speakers_promotes_the_hand_at_once() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let welcoming = Opening {
            auto_accept_speakers: true,
            ..opening()
        };
        service.open(room(), host(), welcoming).unwrap();
        watching(&service);

        let Hand::AutoAccepted(promoted) = service.raise_hand(room(), bob()).unwrap() else {
            panic!("поднятая рука должна быть принята сразу");
        };
        assert_eq!(promoted.role, StreamRole::Speaker);
        assert!(promoted.allowed.can_speak);
        assert!(service.status(room()).unwrap().unwrap().hands.is_empty());
    }

    #[test]
    fn only_whoever_runs_the_stream_grants_rights() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);

        assert_eq!(
            service
                .grant(
                    room(),
                    bob(),
                    ann(),
                    Grant {
                        role: None,
                        can_speak: Some(true),
                        can_video: None,
                        can_screen_share: None,
                    }
                )
                .unwrap(),
            Granted::NotAllowed
        );
    }

    #[test]
    fn granting_the_right_to_speak_lowers_the_hand_it_answers() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);
        service.raise_hand(room(), bob()).unwrap();

        let Granted::Granted(granted) = service
            .grant(
                room(),
                ann(),
                bob(),
                Grant {
                    role: Some(StreamRole::Speaker),
                    can_speak: None,
                    can_video: None,
                    can_screen_share: None,
                },
            )
            .unwrap()
        else {
            panic!("ведущий должен выдать право говорить");
        };
        assert_eq!(granted.role, StreamRole::Speaker);
        assert!(!granted.hand_raised);
        assert!(service.status(room()).unwrap().unwrap().hands.is_empty());
    }

    #[test]
    fn a_participant_the_stream_never_seated_is_granted_nothing() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        assert_eq!(
            service
                .grant(
                    room(),
                    ann(),
                    bob(),
                    Grant {
                        role: Some(StreamRole::Speaker),
                        can_speak: None,
                        can_video: None,
                        can_screen_share: None,
                    }
                )
                .unwrap(),
            Granted::NoSuchParticipant
        );
    }

    #[test]
    fn the_host_is_never_kicked_from_its_own_stream() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        assert_eq!(
            service.kick(room(), ann(), ann()).unwrap(),
            Kicked::CannotKickHost
        );
    }

    #[test]
    fn a_kicked_viewer_leaves_the_roster_and_the_queue() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);
        service.raise_hand(room(), bob()).unwrap();

        assert_eq!(service.kick(room(), ann(), bob()).unwrap(), Kicked::Kicked);
        let snapshot = service.status(room()).unwrap().unwrap();
        assert_eq!(snapshot.viewer_count(), 1);
        assert!(snapshot.hands.is_empty());
        assert_eq!(
            service.kick(room(), ann(), bob()).unwrap(),
            Kicked::NoSuchParticipant
        );
    }

    #[test]
    fn a_reaction_is_counted_where_every_worker_reads_it() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);

        assert_eq!(
            service.react(room(), bob(), "\u{2764}\u{fe0f}").unwrap(),
            Reacted::Counted("\u{2764}\u{fe0f}".to_owned())
        );
        service.react(room(), bob(), "\u{2764}\u{fe0f}").unwrap();
        let snapshot = service.status(room()).unwrap().unwrap();
        assert_eq!(snapshot.reactions["\u{2764}\u{fe0f}"], 2);
    }

    #[test]
    fn a_reaction_longer_than_ten_characters_is_cut_before_it_is_counted() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        let Reacted::Counted(counted) = service
            .react(room(), ann(), &"\u{1f600}".repeat(20))
            .unwrap()
        else {
            panic!("реакция ведущего должна быть сосчитана");
        };

        assert_eq!(counted.chars().count(), 10);
        let snapshot = service.status(room()).unwrap().unwrap();
        assert_eq!(snapshot.reactions.keys().next().unwrap(), &counted);
    }

    #[test]
    fn a_stream_with_reactions_switched_off_counts_none() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let quiet = Opening {
            allow_reactions: false,
            ..opening()
        };
        service.open(room(), host(), quiet).unwrap();
        assert_eq!(
            service.react(room(), ann(), "\u{2764}").unwrap(),
            Reacted::Disabled
        );
    }

    #[test]
    fn whoever_is_not_watching_reacts_to_nothing() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        assert_eq!(
            service.react(room(), bob(), "\u{2764}").unwrap(),
            Reacted::NotIn
        );
    }

    #[test]
    fn a_donation_is_kept_with_who_sent_it() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let paid = Opening {
            allow_donations: true,
            ..opening()
        };
        service.open(room(), host(), paid).unwrap();
        watching(&service);

        let Donated::Donated(donation) = service
            .donate(room(), bob(), "500", "RUB", "спасибо")
            .unwrap()
        else {
            panic!("зритель должен отправить донат");
        };
        assert_eq!(donation.user_id, 8);
        assert_eq!(donation.amount, "500");
        assert_eq!(service.donations(room()).unwrap().len(), 1);
    }

    #[test]
    fn a_stream_with_donations_switched_off_takes_none() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        assert_eq!(
            service.donate(room(), ann(), "500", "RUB", "").unwrap(),
            Donated::Disabled
        );
    }

    #[test]
    fn the_host_changes_the_settings_and_every_worker_sees_them() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);

        let patch = StreamPatch {
            title: Some("Другой".to_owned()),
            allow_donations: Some(true),
            ..StreamPatch::default()
        };
        let Updated::Updated(snapshot) = service.update(room(), ann(), &patch).unwrap() else {
            panic!("ведущий должен менять настройки");
        };
        assert_eq!(snapshot.stream.title, "Другой");
        assert!(
            service
                .status(room())
                .unwrap()
                .unwrap()
                .stream
                .allow_donations
        );
    }

    #[test]
    fn a_viewer_changes_no_settings() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);
        assert_eq!(
            service
                .update(room(), bob(), &StreamPatch::default())
                .unwrap(),
            Updated::NotAllowed
        );
    }

    #[test]
    fn a_viewer_mutes_itself_but_never_unmutes_itself() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);

        let Amended::Amended(amended) = service.mute(room(), bob(), Some(false), None).unwrap()
        else {
            panic!("участник трансляции должен быть найден");
        };
        assert!(amended.is_muted);
    }

    #[test]
    fn only_whoever_may_share_a_screen_shares_it() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        live(&service);
        watching(&service);

        assert_eq!(
            service.share_screen(room(), bob(), true).unwrap(),
            Amended::NotAllowed
        );
        let Amended::Amended(sharing) = service.share_screen(room(), ann(), true).unwrap() else {
            panic!("ведущий должен делиться экраном");
        };
        assert!(sharing.is_screen_sharing);
    }

    #[test]
    fn a_stream_nobody_renews_ends_by_itself() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        live(&service);

        clock.advance(120.0);
        assert!(service.status(room()).unwrap().is_none());
    }

    #[test]
    fn renewing_keeps_a_long_stream_live_with_everyone_watching_it() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        live(&service);
        watching(&service);
        service.react(room(), bob(), "\u{2764}").unwrap();

        clock.advance(90.0);
        assert!(service.renew(room()).unwrap());
        clock.advance(90.0);

        let snapshot = service.status(room()).unwrap().unwrap();
        assert_eq!(snapshot.viewer_count(), 2);
        assert_eq!(snapshot.reactions["\u{2764}"], 1);
    }

    #[test]
    fn without_shared_state_the_stream_refuses_instead_of_answering_for_one_worker() {
        let service = StreamService::new(
            Arc::new(UnavailableStreamRecords::new()),
            Arc::new(MemoryStreamRoster::new()),
            Arc::new(MemoryStreamHands::new()),
            Arc::new(MemoryStreamTally::new()),
            Arc::new(MemoryStreamDonations::new()),
            Arc::new(ManualClock::at(1_000.0)),
        );
        assert_eq!(
            service.open(room(), host(), opening()),
            Err(StateError::Unavailable)
        );
    }
}
