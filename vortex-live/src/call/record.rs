use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::call::kind::CallKind;
use crate::call::membership::MemberState;
use crate::call::participant::CallParticipant;
use crate::call::topology::Topology;

pub const RINGING: &str = "ringing";
pub const ACTIVE: &str = "active";
pub const ENDED: &str = "ended";
pub const CONNECTED_TO_START: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallState {
    #[serde(rename = "ringing")]
    Ringing,
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "ended")]
    Ended,
}

impl CallState {
    pub fn as_str(self) -> &'static str {
        match self {
            CallState::Ringing => RINGING,
            CallState::Active => ACTIVE,
            CallState::Ended => ENDED,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub call_id: String,
    pub room_id: i64,
    pub initiator_id: i64,
    pub kind: CallKind,
    pub state: CallState,
    pub topology: Topology,
    pub participants: BTreeMap<i64, CallParticipant>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub max_participants: u32,
    pub until: f64,
}

impl Call {
    pub fn alive_at(&self, now: f64) -> bool {
        self.until > now && self.state != CallState::Ended
    }

    pub fn connected_count(&self) -> usize {
        self.participants
            .values()
            .filter(|participant| participant.state.on_the_call())
            .count()
    }

    pub fn member(&self, user_id: i64) -> Option<&CallParticipant> {
        self.participants.get(&user_id)
    }

    pub fn with_member(&self, user_id: i64, participant: CallParticipant, until: f64) -> Self {
        let mut changed = self.clone();
        changed.participants.insert(user_id, participant);
        changed.until = until;
        changed
    }

    pub fn started_now(&self, at: String) -> Self {
        if self.state != CallState::Ringing || self.connected_count() < CONNECTED_TO_START {
            return self.clone();
        }
        let mut changed = self.clone();
        changed.state = CallState::Active;
        changed.started_at = Some(at);
        changed
    }

    pub fn ended(&self) -> Self {
        let mut changed = self.clone();
        changed.state = CallState::Ended;
        changed
    }

    pub fn renewed(&self, until: f64) -> Self {
        let mut changed = self.clone();
        changed.until = until;
        changed
    }

    pub fn view(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "room_id": self.room_id,
            "initiator_id": self.initiator_id,
            "call_type": self.kind.as_str(),
            "state": self.state.as_str(),
            "topology": self.topology.as_str(),
            "participant_count": self.connected_count(),
            "participants": self
                .participants
                .values()
                .map(CallParticipant::view)
                .collect::<Vec<Value>>(),
            "created_at": self.created_at,
            "started_at": self.started_at,
        })
    }

    pub fn to_wire(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn parse(wire: &str) -> Option<Self> {
        serde_json::from_str(wire).ok()
    }
}

pub fn seated(participants: Vec<(i64, CallParticipant)>) -> BTreeMap<i64, CallParticipant> {
    participants.into_iter().collect()
}

pub fn state_of(participant: Option<&CallParticipant>) -> Option<MemberState> {
    participant.map(|participant| participant.state)
}

#[cfg(test)]
pub mod tests {
    use super::{seated, Call, CallState};
    use crate::call::kind::CallKind;
    use crate::call::membership::MemberState;
    use crate::call::participant::CallParticipant;
    use crate::call::topology::Topology;
    use crate::identity::person::Person;

    pub fn call() -> Call {
        Call {
            call_id: "abcd".to_owned(),
            room_id: 1,
            initiator_id: 7,
            kind: CallKind::Audio,
            state: CallState::Ringing,
            topology: Topology::Mesh,
            participants: seated(vec![
                (
                    7,
                    CallParticipant::connecting(
                        Person::of(7, "ann", Some("Ann"), None, None),
                        "2026-08-04T09:15:30+00:00".to_owned(),
                    ),
                ),
                (
                    8,
                    CallParticipant::invited(Person::of(8, "bob", None, None, None)),
                ),
            ]),
            created_at: "2026-08-04T09:15:30+00:00".to_owned(),
            started_at: None,
            max_participants: 10,
            until: 1_120.0,
        }
    }

    #[test]
    fn a_call_survives_the_trip_through_the_store() {
        assert_eq!(Call::parse(&call().to_wire()).unwrap(), call());
    }

    #[test]
    fn only_those_on_the_call_are_counted() {
        assert_eq!(call().connected_count(), 1);
    }

    #[test]
    fn a_ringing_call_becomes_active_when_the_second_participant_connects() {
        let call = call();
        let joined = call.with_member(
            8,
            call.member(8)
                .unwrap()
                .joining("2026-08-04T09:16:00+00:00".to_owned()),
            1_240.0,
        );
        let started = joined.started_now("2026-08-04T09:16:00+00:00".to_owned());

        assert_eq!(started.state, CallState::Active);
        assert_eq!(
            started.started_at.as_deref(),
            Some("2026-08-04T09:16:00+00:00")
        );
    }

    #[test]
    fn a_call_with_one_participant_keeps_ringing() {
        let started = call().started_now("2026-08-04T09:16:00+00:00".to_owned());
        assert_eq!(started.state, CallState::Ringing);
        assert_eq!(started.started_at, None);
    }

    #[test]
    fn a_call_that_already_started_does_not_start_again() {
        let mut call = call();
        call.state = CallState::Active;
        call.started_at = Some("2026-08-04T09:16:00+00:00".to_owned());
        let again = call.started_now("2026-08-04T09:20:00+00:00".to_owned());
        assert_eq!(
            again.started_at.as_deref(),
            Some("2026-08-04T09:16:00+00:00")
        );
    }

    #[test]
    fn an_ended_call_is_no_longer_alive_however_long_its_record_lives() {
        assert!(call().alive_at(1_000.0));
        assert!(!call().ended().alive_at(1_000.0));
        assert!(!call().alive_at(1_120.0));
    }

    #[test]
    fn the_room_sees_the_call_with_everyone_in_the_state_they_are_in() {
        let view = call().view();
        assert_eq!(view["call_id"], "abcd");
        assert_eq!(view["call_type"], "group_audio");
        assert_eq!(view["state"], "ringing");
        assert_eq!(view["topology"], "mesh");
        assert_eq!(view["participant_count"], 1);
        assert_eq!(view["participants"][0]["user_id"], 7);
        assert_eq!(view["participants"][1]["state"], "invited");
        assert_eq!(view["started_at"], serde_json::Value::Null);
    }

    #[test]
    fn a_participant_the_call_never_invited_is_not_a_member() {
        assert_eq!(call().member(9), None);
        assert_eq!(call().member(8).unwrap().state, MemberState::Invited);
    }

    #[test]
    fn what_the_store_could_not_have_written_is_not_a_call() {
        assert!(Call::parse("").is_none());
        assert!(Call::parse("{\"call_id\": \"abcd\"}").is_none());
    }
}
