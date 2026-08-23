use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use vortex_proto::room::antispam::config::AntispamConfig;
use vortex_proto::room::avatar::RoomAvatar;
use vortex_proto::room::refusal::RoomRefusal;
use vortex_proto::room::replication::ReplicationMode;
use vortex_proto::room::settings::patch::RoomPatch;
use vortex_proto::room::settings::request::RoomPatchRequest;
use vortex_proto::room::theme::theme::Theme;
use vortex_proto::room::view::{RoomRow, RoomView};

use crate::proto::message::split_micros;

#[pyclass(module = "vortex_chat", name = "RoomSettings", frozen)]
pub struct PyRoomSettings {
    patch: RoomPatch,
    #[pyo3(get)]
    pub refusal: Option<String>,
}

#[pymethods]
impl PyRoomSettings {
    #[getter]
    fn accepted(&self) -> bool {
        self.refusal.is_none()
    }

    #[getter]
    fn name(&self) -> Option<&str> {
        self.patch.name.as_ref().map(|value| value.as_str())
    }

    #[getter]
    fn description(&self) -> Option<&str> {
        self.patch.description.as_ref().map(|value| value.as_str())
    }

    #[getter]
    fn avatar_emoji(&self) -> Option<&str> {
        self.patch.avatar_emoji.as_ref().map(|value| value.as_str())
    }

    #[getter]
    fn is_private(&self) -> Option<bool> {
        self.patch.is_private
    }

    #[getter]
    fn auto_delete_given(&self) -> bool {
        self.patch.auto_delete.is_some()
    }

    #[getter]
    fn auto_delete_seconds(&self) -> Option<i64> {
        self.patch.auto_delete.and_then(|value| value.seconds())
    }

    #[getter]
    fn slow_mode_seconds(&self) -> Option<i64> {
        self.patch.slow_mode.map(|value| value.seconds())
    }

    #[getter]
    fn antispam_enabled(&self) -> Option<bool> {
        self.patch.antispam_enabled
    }

    #[getter]
    fn antispam_config(&self) -> Option<String> {
        self.patch.antispam_config.map(|value| value.written())
    }

    #[getter]
    fn antispam_config_refused(&self) -> bool {
        self.patch.antispam_config_refused
    }

    #[getter]
    fn discussion_enabled(&self) -> Option<bool> {
        self.patch.discussion_enabled
    }

    #[getter]
    fn reactions_type(&self) -> Option<&str> {
        self.patch.reactions_type.map(|value| value.as_str())
    }

    #[getter]
    fn allowed_reactions(&self) -> Option<&str> {
        self.patch
            .allowed_reactions
            .as_ref()
            .map(|value| value.as_str())
    }

    #[getter]
    fn admin_signatures(&self) -> Option<bool> {
        self.patch.admin_signatures
    }

    #[getter]
    fn copy_protection(&self) -> Option<bool> {
        self.patch.copy_protection
    }

    #[getter]
    fn silent_default(&self) -> Option<bool> {
        self.patch.silent_default
    }

    #[getter]
    fn join_approval(&self) -> Option<bool> {
        self.patch.join_approval
    }

    #[getter]
    fn hashtags_enabled(&self) -> Option<bool> {
        self.patch.hashtags_enabled
    }

    fn __repr__(&self) -> String {
        match &self.refusal {
            Some(detail) => format!("<RoomSettings refused={detail}>"),
            None => "<RoomSettings accepted>".to_string(),
        }
    }
}

#[pyfunction]
pub fn room_settings_parse(payload: &str) -> PyRoomSettings {
    let request = match RoomPatchRequest::from_json(payload) {
        Ok(value) => value,
        Err(_) => return refused(RoomRefusal::Name),
    };
    match RoomPatch::read(&request) {
        Ok(patch) => PyRoomSettings {
            patch,
            refusal: None,
        },
        Err(refusal) => refused(refusal),
    }
}

fn refused(refusal: RoomRefusal) -> PyRoomSettings {
    PyRoomSettings {
        patch: RoomPatch::default(),
        refusal: Some(refusal.detail()),
    }
}

#[pyfunction]
pub fn room_name_read(text: &str) -> Option<String> {
    vortex_proto::room::name::RoomName::read(text)
        .ok()
        .map(|value| value.as_str().to_string())
}

#[pyfunction]
pub fn room_description_read(text: &str) -> Option<String> {
    vortex_proto::room::description::RoomDescription::read(text)
        .ok()
        .map(|value| value.as_str().to_string())
}

#[pyfunction]
pub fn room_avatar_given(is_voice: bool) -> String {
    RoomAvatar::given(is_voice).as_str().to_string()
}

#[pyfunction]
pub fn room_replication_mode(text: &str) -> Option<String> {
    ReplicationMode::read(text)
        .ok()
        .map(|mode| mode.as_str().to_string())
}

#[pyfunction]
pub fn room_antispam_config(payload: &str) -> Option<String> {
    AntispamConfig::read(payload).map(|config| config.written())
}

#[pyfunction]
#[pyo3(signature = (wallpaper=None, accent=None, dark_mode=None))]
pub fn room_theme(
    wallpaper: Option<&str>,
    accent: Option<&str>,
    dark_mode: Option<bool>,
) -> Result<String, RoomThemeRefused> {
    Theme::read(wallpaper, accent, dark_mode)
        .map(|theme| theme.written())
        .map_err(|refusal| RoomThemeRefused(refusal.detail()))
}

pub struct RoomThemeRefused(String);

impl From<RoomThemeRefused> for PyErr {
    fn from(refused: RoomThemeRefused) -> PyErr {
        pyo3::exceptions::PyValueError::new_err(refused.0)
    }
}

#[pyfunction]
#[pyo3(signature = (
    id,
    name,
    member_count,
    online_count,
    created_at_us,
    description=None,
    is_private=None,
    is_channel=None,
    is_voice=None,
    invite_code=None,
    avatar_emoji=None,
    avatar_url=None,
    auto_delete_seconds=None,
    slow_mode_seconds=None,
    antispam_enabled=None,
    antispam_config=None,
    creator_id=None,
    theme_json=None,
    discussion_enabled=None,
    reactions_type=None,
    allowed_reactions=None,
    admin_signatures=None,
    copy_protection=None,
    silent_default=None,
    join_approval=None,
    hashtags_enabled=None,
    replication_mode=None,
    is_dm=None,
    voice_participants=None,
))]
#[allow(clippy::too_many_arguments)]
pub fn room_view<'py>(
    py: Python<'py>,
    id: i64,
    name: &str,
    member_count: i64,
    online_count: i64,
    created_at_us: i64,
    description: Option<&str>,
    is_private: Option<bool>,
    is_channel: Option<bool>,
    is_voice: Option<bool>,
    invite_code: Option<&str>,
    avatar_emoji: Option<&str>,
    avatar_url: Option<&str>,
    auto_delete_seconds: Option<i64>,
    slow_mode_seconds: Option<i64>,
    antispam_enabled: Option<bool>,
    antispam_config: Option<&str>,
    creator_id: Option<i64>,
    theme_json: Option<&str>,
    discussion_enabled: Option<bool>,
    reactions_type: Option<&str>,
    allowed_reactions: Option<&str>,
    admin_signatures: Option<bool>,
    copy_protection: Option<bool>,
    silent_default: Option<bool>,
    join_approval: Option<bool>,
    hashtags_enabled: Option<bool>,
    replication_mode: Option<&str>,
    is_dm: Option<bool>,
    voice_participants: Option<Bound<'py, PyList>>,
) -> PyResult<Bound<'py, PyDict>> {
    let view = RoomView::render(RoomRow {
        id,
        name,
        description,
        is_private,
        is_channel,
        is_voice,
        invite_code,
        member_count,
        online_count,
        avatar_emoji,
        avatar_url,
        auto_delete_seconds,
        slow_mode_seconds,
        antispam_enabled,
        antispam_config,
        creator_id,
        created_at: split_micros(created_at_us),
        theme_json,
        discussion_enabled,
        reactions_type,
        allowed_reactions,
        admin_signatures,
        copy_protection,
        silent_default,
        join_approval,
        hashtags_enabled,
        replication_mode,
        is_dm,
    });

    let out = PyDict::new(py);
    out.set_item("id", view.id)?;
    out.set_item("name", &view.name)?;
    out.set_item("description", &view.description)?;
    out.set_item("is_private", view.is_private)?;
    out.set_item("is_channel", view.is_channel)?;
    out.set_item("is_voice", view.is_voice)?;
    out.set_item("invite_code", &view.invite_code)?;
    out.set_item("member_count", view.member_count)?;
    out.set_item("online_count", view.online_count)?;
    out.set_item("avatar_emoji", &view.avatar_emoji)?;
    out.set_item("avatar_url", &view.avatar_url)?;
    out.set_item("auto_delete_seconds", view.auto_delete_seconds)?;
    out.set_item("slow_mode_seconds", view.slow_mode_seconds)?;
    out.set_item("antispam_enabled", view.antispam_enabled)?;
    out.set_item("antispam_config", &view.antispam_config)?;
    out.set_item("creator_id", view.creator_id)?;
    out.set_item("created_at", &view.created_at)?;
    out.set_item("theme_json", &view.theme_json)?;
    out.set_item("discussion_enabled", view.discussion_enabled)?;
    out.set_item("reactions_type", &view.reactions_type)?;
    out.set_item("allowed_reactions", &view.allowed_reactions)?;
    out.set_item("admin_signatures", view.admin_signatures)?;
    out.set_item("copy_protection", view.copy_protection)?;
    out.set_item("silent_default", view.silent_default)?;
    out.set_item("join_approval", view.join_approval)?;
    out.set_item("hashtags_enabled", view.hashtags_enabled)?;
    out.set_item("replication_mode", &view.replication_mode)?;
    out.set_item("is_dm", view.is_dm)?;
    if view.shows_voice_participants() {
        let participants = voice_participants.unwrap_or_else(|| PyList::empty(py));
        out.set_item("voice_participants", &participants)?;
        out.set_item("voice_participant_count", participants.len())?;
    }
    Ok(out)
}
