use std::sync::Arc;

use vortex_auth::account::user_id::UserId;
use vortex_auth::ports::clock::Clock;
use vortex_auth::ports::entropy::Entropy;

use crate::call::call_id::CallId;
use crate::call::kind::CallKind;
use crate::call::membership::MemberState;
use crate::call::outcome::{Added, Declined, Ended, Joined, Left, Started};
use crate::call::participant::CallParticipant;
use crate::call::record::{seated, Call, CallState};
use crate::call::topology::Topology;
use crate::error::{Result, StateError};
use crate::identity::person::Person;
use crate::ports::call_index::CallIndex;
use crate::ports::call_records::CallRecords;
use crate::ports::ring_claims::RingClaims;
use crate::store::swapped::ATTEMPTS;
use crate::time::{lifetime, stamp};
use vortex_core::room::room_id::RoomId;

enum Amendment<T> {
    Write(Box<Call>, T),
    Answer(T),
}

pub struct Sizing {
    pub sfu_available: bool,
    pub threshold: u32,
    pub sfu_max: u32,
}

pub struct GroupCallService {
    records: Arc<dyn CallRecords>,
    index: Arc<dyn CallIndex>,
    rings: Arc<dyn RingClaims>,
    clock: Arc<dyn Clock>,
    entropy: Arc<dyn Entropy>,
}

impl GroupCallService {
    pub fn new(
        records: Arc<dyn CallRecords>,
        index: Arc<dyn CallIndex>,
        rings: Arc<dyn RingClaims>,
        clock: Arc<dyn Clock>,
        entropy: Arc<dyn Entropy>,
    ) -> Self {
        GroupCallService {
            records,
            index,
            rings,
            clock,
            entropy,
        }
    }

    pub fn start(
        &self,
        room: RoomId,
        initiator: UserId,
        kind: CallKind,
        members: Vec<Person>,
        sizing: &Sizing,
    ) -> Result<Started> {
        let now = self.clock.unix_seconds();
        if let Some(running) = self.running(room, now)? {
            return Ok(Started::Already(running.call_id));
        }

        let call = self.drafted(room, initiator, kind, members, sizing, now);
        let identifier = CallId::parse(&call.call_id).map_err(|_| StateError::Unavailable)?;
        if let Some(taken) = self
            .index
            .claim(room, &identifier, call.until, now)?
            .filter(|taken| taken.as_str() != identifier.as_str())
        {
            return Ok(Started::Already(taken.as_str().to_owned()));
        }
        self.records.open(&call, now)?;
        Ok(Started::Fresh(call))
    }

    pub fn join(&self, call: &CallId, user: UserId) -> Result<Joined> {
        self.amend(call, Joined::Missing, |held, now| {
            let Some(member) = held.member(user.value()) else {
                return Amendment::Answer(Joined::NotInvited);
            };
            if member.state.on_the_call() {
                return Amendment::Answer(Joined::Joined(held.clone()));
            }
            let joined = held
                .with_member(
                    user.value(),
                    member.joining(stamp::written(now)),
                    lifetime::presence().expires_at(now),
                )
                .started_now(stamp::written(now));
            Amendment::Write(Box::new(joined.clone()), Joined::Joined(joined))
        })
    }

    pub fn decline(&self, call: &CallId, user: UserId) -> Result<Declined> {
        self.amend(call, Declined::Missing, |held, now| {
            let Some(member) = held.member(user.value()) else {
                return Amendment::Answer(Declined::Declined);
            };
            let declined = held.with_member(
                user.value(),
                member.in_state(MemberState::Declined),
                lifetime::presence().expires_at(now),
            );
            Amendment::Write(Box::new(declined), Declined::Declined)
        })
    }

    pub fn leave(&self, call: &CallId, user: UserId) -> Result<Left> {
        let left = self.amend(call, Left::Missing, |held, now| {
            let until = lifetime::presence().expires_at(now);
            let after = match held.member(user.value()) {
                Some(member) => {
                    held.with_member(user.value(), member.in_state(MemberState::Left), until)
                }
                None => held.renewed(until),
            };
            if after.connected_count() > 0 {
                return Amendment::Write(
                    Box::new(after.clone()),
                    Left::Left {
                        call: after,
                        ended: false,
                    },
                );
            }
            let ended = after.ended();
            Amendment::Write(
                Box::new(ended.clone()),
                Left::Left {
                    call: ended,
                    ended: true,
                },
            )
        })?;

        if let Left::Left {
            call: record,
            ended,
        } = &left
        {
            if *ended {
                self.dismiss(call, record)?;
            }
        }
        Ok(left)
    }

    pub fn add(&self, call: &CallId, actor: UserId, person: Person) -> Result<Added> {
        self.amend(call, Added::Missing, |held, now| {
            if held.member(actor.value()).is_none() {
                return Amendment::Answer(Added::NotAParticipant);
            }
            if held
                .member(person.user_id)
                .is_some_and(|member| !member.state.invitable_again())
            {
                return Amendment::Answer(Added::AlreadyIn);
            }
            let added = held.with_member(
                person.user_id,
                CallParticipant::invited(person.clone()),
                lifetime::presence().expires_at(now),
            );
            Amendment::Write(Box::new(added.clone()), Added::Added(added))
        })
    }

    pub fn end(&self, call: &CallId, actor: UserId) -> Result<Ended> {
        let ended = self.amend(call, Ended::Missing, |held, _now| {
            if held.initiator_id != actor.value() {
                return Amendment::Answer(Ended::NotInitiator);
            }
            let ended = held.ended();
            Amendment::Write(Box::new(ended.clone()), Ended::Ended(ended))
        })?;

        if let Ended::Ended(record) = &ended {
            self.dismiss(call, record)?;
        }
        Ok(ended)
    }

    pub fn ring_out(&self, call: &CallId) -> Result<Option<Call>> {
        let now = self.clock.unix_seconds();
        if !self
            .rings
            .claim(call, lifetime::ring().expires_at(now), now)?
        {
            return Ok(None);
        }
        let ended = self.amend(call, Ended::Missing, |held, _now| {
            if held.state != CallState::Ringing {
                return Amendment::Answer(Ended::NotInitiator);
            }
            let ended = held.ended();
            Amendment::Write(Box::new(ended.clone()), Ended::Ended(ended))
        })?;

        match ended {
            Ended::Ended(record) => {
                self.dismiss(call, &record)?;
                Ok(Some(record))
            }
            _ => Ok(None),
        }
    }

    pub fn status(&self, call: &CallId) -> Result<Option<Call>> {
        let now = self.clock.unix_seconds();
        Ok(self
            .records
            .find(call, now)?
            .filter(|held| held.alive_at(now)))
    }

    pub fn active(&self, room: RoomId) -> Result<Option<Call>> {
        self.running(room, self.clock.unix_seconds())
    }

    pub fn renew(&self, call: &CallId) -> Result<bool> {
        let renewed = self.amend(call, false, |held, now| {
            let until = lifetime::presence().expires_at(now);
            Amendment::Write(Box::new(held.renewed(until)), true)
        })?;
        if renewed {
            let now = self.clock.unix_seconds();
            if let Some(held) = self.records.find(call, now)? {
                if let Some(room) = RoomId::of(held.room_id) {
                    self.index
                        .renew(room, lifetime::presence().expires_at(now), now)?;
                }
            }
        }
        Ok(renewed)
    }

    fn drafted(
        &self,
        room: RoomId,
        initiator: UserId,
        kind: CallKind,
        members: Vec<Person>,
        sizing: &Sizing,
        now: f64,
    ) -> Call {
        let topology =
            Topology::chosen(sizing.sfu_available, members.len() as u32, sizing.threshold);
        let opened_at = stamp::written(now);
        let participants = members
            .into_iter()
            .map(|person| {
                let user_id = person.user_id;
                let participant = if user_id == initiator.value() {
                    CallParticipant::connecting(person, opened_at.clone())
                } else {
                    CallParticipant::invited(person)
                };
                (user_id, participant)
            })
            .collect::<Vec<(i64, CallParticipant)>>();

        Call {
            call_id: CallId::draw(self.entropy.as_ref()).as_str().to_owned(),
            room_id: room.value(),
            initiator_id: initiator.value(),
            kind,
            state: CallState::Ringing,
            topology,
            participants: seated(participants),
            created_at: opened_at,
            started_at: None,
            max_participants: topology.max_participants(sizing.sfu_max),
            until: lifetime::presence().expires_at(now),
        }
    }

    fn running(&self, room: RoomId, now: f64) -> Result<Option<Call>> {
        let Some(claimed) = self.index.find(room, now)? else {
            return Ok(None);
        };
        match self.records.find(&claimed, now)? {
            Some(held) if held.alive_at(now) => Ok(Some(held)),
            _ => {
                self.index.release(room, &claimed, now)?;
                Ok(None)
            }
        }
    }

    fn dismiss(&self, call: &CallId, record: &Call) -> Result<()> {
        let now = self.clock.unix_seconds();
        if let Some(room) = RoomId::of(record.room_id) {
            self.index.release(room, call, now)?;
        }
        self.records.forget(call, now)?;
        Ok(())
    }

    fn amend<T: Clone>(
        &self,
        call: &CallId,
        missing: T,
        mut change: impl FnMut(&Call, f64) -> Amendment<T>,
    ) -> Result<T> {
        for _ in 0..ATTEMPTS {
            let now = self.clock.unix_seconds();
            let Some(held) = self.records.find(call, now)? else {
                return Ok(missing);
            };
            if !held.alive_at(now) {
                return Ok(missing);
            }
            match change(&held, now) {
                Amendment::Answer(outcome) => return Ok(outcome),
                Amendment::Write(replacement, outcome) => {
                    if self
                        .records
                        .swap(call, &held, replacement.as_ref(), now)?
                        .done()
                    {
                        return Ok(outcome);
                    }
                }
            }
        }
        Err(StateError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{GroupCallService, Sizing};
    use crate::call::call_id::CallId;
    use crate::call::kind::CallKind;
    use crate::call::memory::{MemoryCallIndex, MemoryCallRecords, MemoryRingClaims};
    use crate::call::outcome::{Added, Declined, Ended, Joined, Left, Started};
    use crate::call::record::CallState;
    use crate::call::topology::Topology;
    use crate::call::unavailable::UnavailableCallRecords;
    use crate::error::StateError;
    use crate::identity::person::Person;
    use vortex_auth::account::user_id::UserId;
    use vortex_auth::random::fixed_entropy::FixedEntropy;
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

    fn members() -> Vec<Person> {
        vec![
            Person::of(7, "ann", Some("Ann"), None, None),
            Person::of(8, "bob", None, None, None),
        ]
    }

    fn mesh() -> Sizing {
        Sizing {
            sfu_available: false,
            threshold: 6,
            sfu_max: 200,
        }
    }

    fn service(clock: Arc<ManualClock>) -> GroupCallService {
        GroupCallService::new(
            Arc::new(MemoryCallRecords::new()),
            Arc::new(MemoryCallIndex::new()),
            Arc::new(MemoryRingClaims::new()),
            clock,
            Arc::new(FixedEntropy::counting_from(0)),
        )
    }

    fn started(service: &GroupCallService) -> CallId {
        match service
            .start(room(), ann(), CallKind::Audio, members(), &mesh())
            .unwrap()
        {
            Started::Fresh(call) => CallId::parse(&call.call_id).unwrap(),
            Started::Already(call) => CallId::parse(&call).unwrap(),
        }
    }

    #[test]
    fn starting_a_call_rings_everyone_the_room_holds() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let Started::Fresh(call) = service
            .start(room(), ann(), CallKind::Audio, members(), &mesh())
            .unwrap()
        else {
            panic!("первый звонок в комнате не должен быть повтором");
        };

        assert_eq!(call.state, CallState::Ringing);
        assert_eq!(call.topology, Topology::Mesh);
        assert_eq!(call.max_participants, 10);
        assert_eq!(call.connected_count(), 1);
        assert_eq!(call.member(8).unwrap().state.as_str(), "invited");
    }

    #[test]
    fn a_room_that_already_rings_does_not_ring_a_second_call() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let first = started(&service);

        let Started::Already(again) = service
            .start(room(), bob(), CallKind::Video, members(), &mesh())
            .unwrap()
        else {
            panic!("второй звонок в той же комнате должен вернуть первый");
        };
        assert_eq!(again, first.as_str());
    }

    #[test]
    fn a_large_room_is_started_on_the_forwarding_unit() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let crowd = (7..20)
            .map(|id| Person::of(id, "member", None, None, None))
            .collect();
        let Started::Fresh(call) = service
            .start(
                room(),
                ann(),
                CallKind::Video,
                crowd,
                &Sizing {
                    sfu_available: true,
                    threshold: 6,
                    sfu_max: 200,
                },
            )
            .unwrap()
        else {
            panic!("первый звонок в комнате не должен быть повтором");
        };

        assert_eq!(call.topology, Topology::Sfu);
        assert_eq!(call.max_participants, 200);
    }

    #[test]
    fn the_second_participant_to_connect_makes_the_call_active() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);

        let Joined::Joined(after) = service.join(&call, bob()).unwrap() else {
            panic!("приглашённый участник должен подключиться");
        };
        assert_eq!(after.state, CallState::Active);
        assert!(after.started_at.is_some());
        assert_eq!(after.connected_count(), 2);
    }

    #[test]
    fn nobody_the_call_did_not_invite_joins_it() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);
        assert_eq!(
            service.join(&call, UserId::of(9).unwrap()).unwrap(),
            Joined::NotInvited
        );
    }

    #[test]
    fn joining_twice_keeps_the_moment_of_the_first_join() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        let call = started(&service);
        service.join(&call, bob()).unwrap();

        clock.advance(5.0);
        let Joined::Joined(after) = service.join(&call, bob()).unwrap() else {
            panic!("повторное подключение должно вернуть тот же звонок");
        };
        assert_eq!(
            after.member(8).unwrap().joined_at.as_deref(),
            Some("1970-01-01T00:16:40+00:00")
        );
    }

    #[test]
    fn a_call_nobody_started_is_missing_everywhere() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let nowhere = CallId::parse("neverstarted").unwrap();

        assert_eq!(service.join(&nowhere, ann()).unwrap(), Joined::Missing);
        assert_eq!(service.decline(&nowhere, ann()).unwrap(), Declined::Missing);
        assert_eq!(service.leave(&nowhere, ann()).unwrap(), Left::Missing);
        assert_eq!(service.end(&nowhere, ann()).unwrap(), Ended::Missing);
        assert!(service.status(&nowhere).unwrap().is_none());
    }

    #[test]
    fn declining_leaves_the_call_ringing_for_the_others() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);

        assert_eq!(service.decline(&call, bob()).unwrap(), Declined::Declined);
        let held = service.status(&call).unwrap().unwrap();
        assert_eq!(held.member(8).unwrap().state.as_str(), "declined");
        assert_eq!(held.state, CallState::Ringing);
    }

    #[test]
    fn the_call_ends_when_the_last_participant_leaves_and_ends_only_once() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);

        let Left::Left { ended, .. } = service.leave(&call, ann()).unwrap() else {
            panic!("участник звонка должен уйти");
        };
        assert!(ended);
        assert_eq!(service.leave(&call, ann()).unwrap(), Left::Missing);
        assert!(service.active(room()).unwrap().is_none());
    }

    #[test]
    fn a_call_with_someone_still_on_it_does_not_end_when_another_leaves() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);
        service.join(&call, bob()).unwrap();

        let Left::Left { ended, .. } = service.leave(&call, ann()).unwrap() else {
            panic!("участник звонка должен уйти");
        };
        assert!(!ended);
        assert!(service.active(room()).unwrap().is_some());
    }

    #[test]
    fn only_the_initiator_ends_the_call_for_everyone() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);

        assert_eq!(service.end(&call, bob()).unwrap(), Ended::NotInitiator);
        let Ended::Ended(record) = service.end(&call, ann()).unwrap() else {
            panic!("инициатор должен завершить звонок");
        };
        assert_eq!(record.state, CallState::Ended);
        assert!(service.status(&call).unwrap().is_none());
    }

    #[test]
    fn a_participant_added_mid_call_is_invited_and_may_be_added_only_once() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);
        let carol = Person::of(9, "carol", None, None, None);

        let Added::Added(after) = service.add(&call, ann(), carol.clone()).unwrap() else {
            panic!("участника звонка должно быть можно позвать");
        };
        assert_eq!(after.member(9).unwrap().state.as_str(), "invited");
        assert_eq!(service.add(&call, ann(), carol).unwrap(), Added::AlreadyIn);
    }

    #[test]
    fn somebody_outside_the_call_invites_nobody_into_it() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);
        assert_eq!(
            service
                .add(
                    &call,
                    UserId::of(9).unwrap(),
                    Person::of(10, "dave", None, None, None)
                )
                .unwrap(),
            Added::NotAParticipant
        );
    }

    #[test]
    fn whoever_declined_may_be_invited_again() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);
        service.decline(&call, bob()).unwrap();

        let Added::Added(after) = service
            .add(&call, ann(), Person::of(8, "bob", None, None, None))
            .unwrap()
        else {
            panic!("отклонившего участника должно быть можно позвать снова");
        };
        assert_eq!(after.member(8).unwrap().state.as_str(), "invited");
    }

    #[test]
    fn a_call_nobody_answered_is_rung_out_exactly_once() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);

        assert!(service.ring_out(&call).unwrap().is_some());
        assert!(service.ring_out(&call).unwrap().is_none());
        assert!(service.active(room()).unwrap().is_none());
    }

    #[test]
    fn a_call_that_became_active_is_not_rung_out() {
        let service = service(Arc::new(ManualClock::at(1_000.0)));
        let call = started(&service);
        service.join(&call, bob()).unwrap();

        assert!(service.ring_out(&call).unwrap().is_none());
        assert!(service.active(room()).unwrap().is_some());
    }

    #[test]
    fn a_call_nobody_renews_stops_holding_the_room() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        let call = started(&service);

        clock.advance(120.0);
        assert!(service.status(&call).unwrap().is_none());
        assert!(service.active(room()).unwrap().is_none());
    }

    #[test]
    fn renewing_keeps_a_long_call_alive() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        let call = started(&service);

        clock.advance(90.0);
        assert!(service.renew(&call).unwrap());
        clock.advance(90.0);
        assert!(service.status(&call).unwrap().is_some());
    }

    #[test]
    fn a_room_whose_call_expired_may_start_a_new_one() {
        let clock = Arc::new(ManualClock::at(1_000.0));
        let service = service(clock.clone());
        let first = started(&service);

        clock.advance(120.0);
        let second = started(&service);
        assert_ne!(first.as_str(), second.as_str());
    }

    #[test]
    fn without_shared_state_the_call_refuses_instead_of_answering_for_one_worker() {
        let service = GroupCallService::new(
            Arc::new(UnavailableCallRecords::new()),
            Arc::new(MemoryCallIndex::new()),
            Arc::new(MemoryRingClaims::new()),
            Arc::new(ManualClock::at(1_000.0)),
            Arc::new(FixedEntropy::counting_from(0)),
        );
        assert_eq!(
            service.start(room(), ann(), CallKind::Audio, members(), &mesh()),
            Err(StateError::Unavailable)
        );
    }
}
