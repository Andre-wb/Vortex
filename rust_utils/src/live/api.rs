use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde_json::{json, Value};
use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;
use vortex_live::call::call_id::CallId;
use vortex_live::call::kind::CallKind;
use vortex_live::call::outcome::{Added, Declined, Ended, Joined, Left, Started};
use vortex_live::call::record::Call;
use vortex_live::call::service::Sizing;
use vortex_live::error::StateError;
use vortex_live::identity::person::Person;
use vortex_live::recording::mark::status_view;
use vortex_live::stream::hands::raised;
use vortex_live::stream::outcome::{
    Amended, Donated, Granted, Hand, Kicked, Opened, Reacted, Seated, Stopped, Unseated, Updated,
};
use vortex_live::stream::record::Opening;
use vortex_live::stream::role::StreamRole;
use vortex_live::stream::service::Grant;
use vortex_live::stream::settings::StreamPatch;
use vortex_live::voice::patch::MutePatch;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::live::convert::value_to_py;
use crate::live::shared;

type Identity = (i64, String, Option<String>, Option<String>, Option<String>);

fn unavailable(error: StateError) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}

fn room(value: i64) -> PyResult<RoomId> {
    RoomId::of(value)
        .ok_or_else(|| PyValueError::new_err("номер комнаты должен быть положительным"))
}

fn account(value: i64) -> PyResult<UserId> {
    UserId::of(value)
        .ok_or_else(|| PyValueError::new_err("номер учётной записи должен быть положительным"))
}

fn call_of(value: &str) -> PyResult<CallId> {
    CallId::parse(value).map_err(|refusal| PyValueError::new_err(refusal.to_string()))
}

fn person_of(identity: &Identity) -> Person {
    let (user_id, username, display_name, avatar_emoji, avatar_url) = identity;
    Person::of(
        *user_id,
        username,
        display_name.as_deref(),
        avatar_emoji.as_deref(),
        avatar_url.as_deref(),
    )
}

fn answer(py: Python<'_>, value: Value) -> PyResult<PyObject> {
    value_to_py(py, &value)
}

fn call_view(call: &Call) -> Value {
    call.view()
}

#[pyfunction]
#[pyo3(signature = (url, pool_size=None, key_prefix=None))]
pub fn live_connect_redis(
    py: Python<'_>,
    url: &str,
    pool_size: Option<usize>,
    key_prefix: Option<String>,
) -> PyResult<bool> {
    let mut config = RedisConfig::new(url);
    if let Some(size) = pool_size {
        config = config.pool_size(size);
    }
    if let Some(prefix) = key_prefix {
        config = config.key_prefix(prefix);
    }

    match py.allow_threads(|| shared::connect(config)) {
        Ok(()) => Ok(true),
        Err(BackboneError::Unconfigured) => Ok(false),
        Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
    }
}

#[pyfunction]
pub fn live_mode() -> &'static str {
    shared::mode()
}

#[pyfunction]
pub fn live_is_shared() -> bool {
    shared::is_shared()
}

#[pyfunction]
pub fn live_voice_join(py: Python<'_>, room_id: i64, identity: Identity) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let person = person_of(&identity);
    let sessions = shared::sessions();
    let (joined, listed) = py
        .allow_threads(|| {
            let joined = sessions.voice.join(channel, &person)?;
            let listed = sessions.voice.participants(channel)?;
            Ok::<_, StateError>((joined, listed))
        })
        .map_err(unavailable)?;

    answer(
        py,
        json!({
            "already_in": joined.already_in(),
            "participant": joined.participant().view(),
            "participants": listed.iter().map(|held| held.view()).collect::<Vec<Value>>(),
        }),
    )
}

#[pyfunction]
pub fn live_voice_leave(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let (left, listed) = py
        .allow_threads(|| {
            let left = sessions.voice.leave(channel, user)?;
            let listed = sessions.voice.participants(channel)?;
            Ok::<_, StateError>((left, listed))
        })
        .map_err(unavailable)?;

    answer(
        py,
        json!({
            "left": left.is_some(),
            "participant": left.map(|held| held.view()),
            "participants": listed.iter().map(|held| held.view()).collect::<Vec<Value>>(),
        }),
    )
}

#[pyfunction]
pub fn live_voice_participants(py: Python<'_>, room_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    let listed = py
        .allow_threads(|| sessions.voice.participants(channel))
        .map_err(unavailable)?;
    answer(
        py,
        Value::Array(listed.iter().map(|held| held.view()).collect()),
    )
}

#[pyfunction]
pub fn live_voice_count(py: Python<'_>, room_id: i64) -> PyResult<usize> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    py.allow_threads(|| sessions.voice.count(channel))
        .map_err(unavailable)
}

#[pyfunction]
pub fn live_voice_find(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let held = py
        .allow_threads(|| sessions.voice.find(channel, user))
        .map_err(unavailable)?;
    answer(py, held.map(|held| held.view()).unwrap_or(Value::Null))
}

#[pyfunction]
#[pyo3(signature = (room_id, user_id, is_muted=None, is_video=None))]
pub fn live_voice_mute(
    py: Python<'_>,
    room_id: i64,
    user_id: i64,
    is_muted: Option<bool>,
    is_video: Option<bool>,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let amended = py
        .allow_threads(|| {
            sessions
                .voice
                .amend(channel, user, MutePatch::new(is_muted, is_video))
        })
        .map_err(unavailable)?;
    answer(py, amended.map(|held| held.view()).unwrap_or(Value::Null))
}

#[pyfunction]
pub fn live_voice_renew(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<bool> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    py.allow_threads(|| {
        let renewed = sessions.voice.renew(channel, user)?;
        sessions.stage.renew(channel)?;
        sessions.recording.renew(channel)?;
        Ok::<_, StateError>(renewed)
    })
    .map_err(unavailable)
}

#[pyfunction]
pub fn live_stage_open(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<Vec<i64>> {
    let channel = room(room_id)?;
    let speaker = account(user_id)?;
    let sessions = shared::sessions();
    let stage = py
        .allow_threads(|| sessions.stage.open(channel, speaker))
        .map_err(unavailable)?;
    Ok(stage.speakers)
}

#[pyfunction]
pub fn live_stage_close(py: Python<'_>, room_id: i64) -> PyResult<bool> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    py.allow_threads(|| sessions.stage.close(channel))
        .map_err(unavailable)
}

#[pyfunction]
pub fn live_stage_status(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    let status = py
        .allow_threads(|| sessions.stage.status(channel))
        .map_err(unavailable)?;
    answer(py, status.view(user_id))
}

#[pyfunction]
pub fn live_stage_add(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<Option<Vec<i64>>> {
    let channel = room(room_id)?;
    let speaker = account(user_id)?;
    let sessions = shared::sessions();
    Ok(py
        .allow_threads(|| sessions.stage.add(channel, speaker))
        .map_err(unavailable)?
        .map(|stage| stage.speakers))
}

#[pyfunction]
pub fn live_stage_remove(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<Option<Vec<i64>>> {
    let channel = room(room_id)?;
    let speaker = account(user_id)?;
    let sessions = shared::sessions();
    Ok(py
        .allow_threads(|| sessions.stage.remove(channel, speaker))
        .map_err(unavailable)?
        .map(|stage| stage.speakers))
}

#[pyfunction]
pub fn live_recording_start(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let starter = account(user_id)?;
    let sessions = shared::sessions();
    let started = py
        .allow_threads(|| {
            let listed = sessions.voice.participants(channel)?;
            let attending = listed.iter().map(|held| held.user_id).collect();
            sessions.recording.start(channel, starter, attending)
        })
        .map_err(unavailable)?;

    answer(
        py,
        json!({
            "recording": true,
            "already_started": started.already_started(),
            "started_at": started.mark().started_at,
        }),
    )
}

#[pyfunction]
pub fn live_recording_stop(py: Python<'_>, room_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    let stopped = py
        .allow_threads(|| sessions.recording.stop(channel))
        .map_err(unavailable)?;
    answer(
        py,
        match stopped {
            Some(mark) => json!({"stopped": true, "started_at": mark.started_at}),
            None => json!({"stopped": false, "started_at": null}),
        },
    )
}

#[pyfunction]
pub fn live_recording_status(py: Python<'_>, room_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    let held = py
        .allow_threads(|| sessions.recording.status(channel))
        .map_err(unavailable)?;
    answer(py, status_view(held.as_ref()))
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn live_call_start(
    py: Python<'_>,
    room_id: i64,
    initiator_id: i64,
    call_type: &str,
    members: Vec<Identity>,
    sfu_available: bool,
    threshold: u32,
    sfu_max: u32,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let initiator = account(initiator_id)?;
    let kind = CallKind::parse(call_type)
        .ok_or_else(|| PyValueError::new_err("неизвестный тип звонка"))?;
    let seated: Vec<Person> = members.iter().map(person_of).collect();
    let sizing = Sizing {
        sfu_available,
        threshold,
        sfu_max,
    };

    let sessions = shared::sessions();
    let started = py
        .allow_threads(|| {
            sessions
                .calls
                .start(channel, initiator, kind, seated, &sizing)
        })
        .map_err(unavailable)?;

    answer(
        py,
        match started {
            Started::Fresh(call) => json!({
                "already_active": false,
                "call_id": call.call_id,
                "topology": call.topology.as_str(),
                "call": call_view(&call),
            }),
            Started::Already(call_id) => json!({
                "already_active": true,
                "call_id": call_id,
                "topology": Value::Null,
                "call": Value::Null,
            }),
        },
    )
}

#[pyfunction]
pub fn live_call_join(py: Python<'_>, call_id: &str, user_id: i64) -> PyResult<PyObject> {
    let identifier = call_of(call_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let joined = py
        .allow_threads(|| sessions.calls.join(&identifier, user))
        .map_err(unavailable)?;

    answer(
        py,
        match joined {
            Joined::Joined(call) => json!({"status": "ok", "call": call_view(&call)}),
            Joined::NotInvited => json!({"status": "not_invited"}),
            Joined::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_call_decline(py: Python<'_>, call_id: &str, user_id: i64) -> PyResult<&'static str> {
    let identifier = call_of(call_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    Ok(
        match py
            .allow_threads(|| sessions.calls.decline(&identifier, user))
            .map_err(unavailable)?
        {
            Declined::Declined => "ok",
            Declined::Missing => "missing",
        },
    )
}

#[pyfunction]
pub fn live_call_leave(py: Python<'_>, call_id: &str, user_id: i64) -> PyResult<PyObject> {
    let identifier = call_of(call_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let left = py
        .allow_threads(|| sessions.calls.leave(&identifier, user))
        .map_err(unavailable)?;

    answer(
        py,
        match left {
            Left::Left { call, ended } => {
                json!({"status": "ok", "ended": ended, "call": call_view(&call)})
            }
            Left::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_call_add(
    py: Python<'_>,
    call_id: &str,
    actor_id: i64,
    identity: Identity,
) -> PyResult<PyObject> {
    let identifier = call_of(call_id)?;
    let actor = account(actor_id)?;
    let person = person_of(&identity);
    let sessions = shared::sessions();
    let added = py
        .allow_threads(|| sessions.calls.add(&identifier, actor, person))
        .map_err(unavailable)?;

    answer(
        py,
        match added {
            Added::Added(call) => json!({"status": "ok", "call": call_view(&call)}),
            Added::NotAParticipant => json!({"status": "not_a_participant"}),
            Added::AlreadyIn => json!({"status": "already_in"}),
            Added::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_call_end(py: Python<'_>, call_id: &str, actor_id: i64) -> PyResult<PyObject> {
    let identifier = call_of(call_id)?;
    let actor = account(actor_id)?;
    let sessions = shared::sessions();
    let ended = py
        .allow_threads(|| sessions.calls.end(&identifier, actor))
        .map_err(unavailable)?;

    answer(
        py,
        match ended {
            Ended::Ended(call) => json!({"status": "ok", "call": call_view(&call)}),
            Ended::NotInitiator => json!({"status": "not_initiator"}),
            Ended::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_call_ring_out(py: Python<'_>, call_id: &str) -> PyResult<PyObject> {
    let identifier = call_of(call_id)?;
    let sessions = shared::sessions();
    let rung = py
        .allow_threads(|| sessions.calls.ring_out(&identifier))
        .map_err(unavailable)?;
    answer(py, rung.map(|call| call_view(&call)).unwrap_or(Value::Null))
}

#[pyfunction]
pub fn live_call_status(py: Python<'_>, call_id: &str) -> PyResult<PyObject> {
    let identifier = call_of(call_id)?;
    let sessions = shared::sessions();
    let held = py
        .allow_threads(|| sessions.calls.status(&identifier))
        .map_err(unavailable)?;
    answer(py, held.map(|call| call_view(&call)).unwrap_or(Value::Null))
}

#[pyfunction]
pub fn live_call_active(py: Python<'_>, room_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    let held = py
        .allow_threads(|| sessions.calls.active(channel))
        .map_err(unavailable)?;
    answer(py, held.map(|call| call_view(&call)).unwrap_or(Value::Null))
}

#[pyfunction]
pub fn live_call_renew(py: Python<'_>, call_id: &str) -> PyResult<bool> {
    let identifier = call_of(call_id)?;
    let sessions = shared::sessions();
    py.allow_threads(|| sessions.calls.renew(&identifier))
        .map_err(unavailable)
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn live_stream_open(
    py: Python<'_>,
    room_id: i64,
    host: Identity,
    title: &str,
    description: &str,
    allow_reactions: bool,
    allow_donations: bool,
    donation_card: &str,
    donation_message: &str,
    auto_accept_speakers: bool,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let person = person_of(&host);
    let opening = Opening {
        title: title.to_owned(),
        description: description.to_owned(),
        allow_reactions,
        allow_donations,
        donation_card: donation_card.to_owned(),
        donation_message: donation_message.to_owned(),
        auto_accept_speakers,
    };

    let sessions = shared::sessions();
    let opened = py
        .allow_threads(|| sessions.streams.open(channel, person, opening))
        .map_err(unavailable)?;

    answer(
        py,
        match opened {
            Opened::Fresh(snapshot) => json!({"status": "ok", "stream": snapshot.view()}),
            Opened::AlreadyLive => json!({"status": "already_live"}),
        },
    )
}

#[pyfunction]
pub fn live_stream_stop(py: Python<'_>, room_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    let stopped = py
        .allow_threads(|| sessions.streams.stop(channel))
        .map_err(unavailable)?;

    answer(
        py,
        match stopped {
            Stopped::Stopped { peak } => json!({"status": "ok", "viewer_peak": peak}),
            Stopped::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_stream_join(
    py: Python<'_>,
    room_id: i64,
    identity: Identity,
    runs_the_room: bool,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let person = person_of(&identity);
    let sessions = shared::sessions();
    let seated = py
        .allow_threads(|| sessions.streams.join(channel, person, runs_the_room))
        .map_err(unavailable)?;

    answer(
        py,
        match seated {
            Seated::Fresh(snapshot) => {
                json!({"status": "ok", "already_in": false, "stream": snapshot.view()})
            }
            Seated::Already(snapshot) => {
                json!({"status": "ok", "already_in": true, "stream": snapshot.view()})
            }
            Seated::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_stream_leave(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let left = py
        .allow_threads(|| sessions.streams.leave(channel, user))
        .map_err(unavailable)?;

    answer(
        py,
        match left {
            Unseated::Left { host_left } => json!({"status": "ok", "stream_ended": host_left}),
            Unseated::NotIn => json!({"status": "not_in"}),
            Unseated::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_stream_status(py: Python<'_>, room_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    let held = py
        .allow_threads(|| sessions.streams.status(channel))
        .map_err(unavailable)?;
    answer(
        py,
        held.map(|snapshot| snapshot.view()).unwrap_or(Value::Null),
    )
}

#[pyfunction]
pub fn live_stream_raise_hand(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let hand = py
        .allow_threads(|| sessions.streams.raise_hand(channel, user))
        .map_err(unavailable)?;

    answer(
        py,
        match hand {
            Hand::Raised => json!({"status": "raised"}),
            Hand::AutoAccepted(participant) => {
                json!({"status": "auto_accepted", "participant": participant.view()})
            }
            Hand::AlreadySpeaks => json!({"status": "already_speaks"}),
            Hand::NotIn => json!({"status": "not_in"}),
            _ => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_stream_lower_hand(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let hand = py
        .allow_threads(|| sessions.streams.lower_hand(channel, user))
        .map_err(unavailable)?;

    answer(
        py,
        match hand {
            Hand::Lowered => json!({"status": "lowered"}),
            Hand::NotIn => json!({"status": "not_in"}),
            _ => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_stream_hands(py: Python<'_>, room_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    let held = py
        .allow_threads(|| sessions.streams.status(channel))
        .map_err(unavailable)?;

    answer(
        py,
        match held {
            Some(snapshot) => Value::Array(raised(&snapshot.hands, &snapshot.participants)),
            None => Value::Null,
        },
    )
}

#[pyfunction]
#[pyo3(signature = (room_id, actor_id, target_id, role=None, can_speak=None, can_video=None, can_screen_share=None))]
#[allow(clippy::too_many_arguments)]
pub fn live_stream_grant(
    py: Python<'_>,
    room_id: i64,
    actor_id: i64,
    target_id: i64,
    role: Option<&str>,
    can_speak: Option<bool>,
    can_video: Option<bool>,
    can_screen_share: Option<bool>,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let actor = account(actor_id)?;
    let target = account(target_id)?;
    let asked = match role {
        Some(value) => Some(
            StreamRole::parse(value)
                .ok_or_else(|| PyValueError::new_err("неизвестная роль в трансляции"))?,
        ),
        None => None,
    };

    let sessions = shared::sessions();
    let granted = py
        .allow_threads(|| {
            sessions.streams.grant(
                channel,
                actor,
                target,
                Grant {
                    role: asked,
                    can_speak,
                    can_video,
                    can_screen_share,
                },
            )
        })
        .map_err(unavailable)?;

    answer(
        py,
        match granted {
            Granted::Granted(participant) => {
                json!({"status": "ok", "participant": participant.view()})
            }
            Granted::NotAllowed => json!({"status": "not_allowed"}),
            Granted::NoSuchParticipant => json!({"status": "no_such_participant"}),
            Granted::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_stream_kick(
    py: Python<'_>,
    room_id: i64,
    actor_id: i64,
    target_id: i64,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let actor = account(actor_id)?;
    let target = account(target_id)?;
    let sessions = shared::sessions();
    let kicked = py
        .allow_threads(|| sessions.streams.kick(channel, actor, target))
        .map_err(unavailable)?;

    answer(
        py,
        match kicked {
            Kicked::Kicked => json!({"status": "ok"}),
            Kicked::NotAllowed => json!({"status": "not_allowed"}),
            Kicked::NoSuchParticipant => json!({"status": "no_such_participant"}),
            Kicked::CannotKickHost => json!({"status": "cannot_kick_host"}),
            Kicked::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_stream_react(
    py: Python<'_>,
    room_id: i64,
    user_id: i64,
    emoji: &str,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let reacted = py
        .allow_threads(|| sessions.streams.react(channel, user, emoji))
        .map_err(unavailable)?;

    answer(
        py,
        match reacted {
            Reacted::Counted(counted) => json!({"status": "ok", "emoji": counted}),
            Reacted::Disabled => json!({"status": "disabled"}),
            Reacted::NotIn => json!({"status": "not_in"}),
            Reacted::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
pub fn live_stream_donate(
    py: Python<'_>,
    room_id: i64,
    user_id: i64,
    amount: &str,
    currency: &str,
    message: &str,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let donated = py
        .allow_threads(|| {
            sessions
                .streams
                .donate(channel, user, amount, currency, message)
        })
        .map_err(unavailable)?;

    answer(
        py,
        match donated {
            Donated::Donated(donation) => json!({"status": "ok", "donation": donation.view()}),
            Donated::Disabled => json!({"status": "disabled"}),
            Donated::NotIn => json!({"status": "not_in"}),
            Donated::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
#[pyo3(signature = (room_id, actor_id, title=None, description=None, allow_reactions=None, allow_donations=None, donation_card=None, donation_message=None, auto_accept_speakers=None))]
#[allow(clippy::too_many_arguments)]
pub fn live_stream_update(
    py: Python<'_>,
    room_id: i64,
    actor_id: i64,
    title: Option<String>,
    description: Option<String>,
    allow_reactions: Option<bool>,
    allow_donations: Option<bool>,
    donation_card: Option<String>,
    donation_message: Option<String>,
    auto_accept_speakers: Option<bool>,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let actor = account(actor_id)?;
    let patch = StreamPatch {
        title,
        description,
        allow_reactions,
        allow_donations,
        donation_card,
        donation_message,
        auto_accept_speakers,
    };

    let sessions = shared::sessions();
    let updated = py
        .allow_threads(|| sessions.streams.update(channel, actor, &patch))
        .map_err(unavailable)?;

    answer(
        py,
        match updated {
            Updated::Updated(snapshot) => json!({"status": "ok", "stream": snapshot.view()}),
            Updated::NotAllowed => json!({"status": "not_allowed"}),
            Updated::Missing => json!({"status": "missing"}),
        },
    )
}

#[pyfunction]
#[pyo3(signature = (room_id, user_id, is_muted=None, is_video_on=None))]
pub fn live_stream_mute(
    py: Python<'_>,
    room_id: i64,
    user_id: i64,
    is_muted: Option<bool>,
    is_video_on: Option<bool>,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let amended = py
        .allow_threads(|| sessions.streams.mute(channel, user, is_muted, is_video_on))
        .map_err(unavailable)?;
    answer(py, amendment(amended))
}

#[pyfunction]
pub fn live_stream_share_screen(
    py: Python<'_>,
    room_id: i64,
    user_id: i64,
    sharing: bool,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let user = account(user_id)?;
    let sessions = shared::sessions();
    let amended = py
        .allow_threads(|| sessions.streams.share_screen(channel, user, sharing))
        .map_err(unavailable)?;
    answer(py, amendment(amended))
}

#[pyfunction]
pub fn live_stream_renew(py: Python<'_>, room_id: i64) -> PyResult<bool> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    py.allow_threads(|| sessions.streams.renew(channel))
        .map_err(unavailable)
}

#[pyfunction]
pub fn live_schedule_plan(
    py: Python<'_>,
    room_id: i64,
    title: &str,
    scheduled_at: &str,
    host_id: i64,
    host_name: &str,
) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    let planned = py
        .allow_threads(|| {
            sessions
                .schedule
                .plan(channel, title, scheduled_at, host_id, host_name)
        })
        .map_err(unavailable)?;
    answer(py, planned.map(|entry| entry.view()).unwrap_or(Value::Null))
}

#[pyfunction]
pub fn live_schedule_find(py: Python<'_>, room_id: i64) -> PyResult<PyObject> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    let planned = py
        .allow_threads(|| sessions.schedule.find(channel))
        .map_err(unavailable)?;
    answer(py, planned.map(|entry| entry.view()).unwrap_or(Value::Null))
}

#[pyfunction]
pub fn live_schedule_forget(py: Python<'_>, room_id: i64) -> PyResult<bool> {
    let channel = room(room_id)?;
    let sessions = shared::sessions();
    py.allow_threads(|| sessions.schedule.forget(channel))
        .map_err(unavailable)
}

#[pyfunction]
pub fn live_schedule_claim_due(py: Python<'_>) -> PyResult<PyObject> {
    let sessions = shared::sessions();
    let claimed = py
        .allow_threads(|| sessions.schedule.claim_due())
        .map_err(unavailable)?;

    answer(
        py,
        match claimed {
            Some(entry) => json!({
                "room_id": entry.room_id,
                "title": entry.title,
                "scheduled_at": entry.scheduled_at,
                "host_id": entry.host_id,
                "host_name": entry.host_name,
            }),
            None => Value::Null,
        },
    )
}

fn amendment(amended: Amended) -> Value {
    match amended {
        Amended::Amended(participant) => json!({"status": "ok", "participant": participant.view()}),
        Amended::NotAllowed => json!({"status": "not_allowed"}),
        Amended::Missing => json!({"status": "missing"}),
    }
}
