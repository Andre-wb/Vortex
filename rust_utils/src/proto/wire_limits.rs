use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_proto::message::limits::{
    CLIENT_STAMP_WINDOW_SECS, MAX_CIPHERTEXT_HEX, MAX_FRAME_TEXT, MAX_MENTIONS, MENTION_MAX_LEN,
    MENTION_MIN_LEN, MIN_CIPHERTEXT_HEX,
};
use vortex_proto::room::limits::{
    ALLOWED_REACTIONS_MAX_LEN, AVATAR_MAX_LEN, DEFAULT_MAX_MEMBERS, DESCRIPTION_MAX_LEN,
    NAME_MAX_LEN, NAME_MIN_LEN,
};
use vortex_proto::wrap::limits::{CIPHERTEXT_MIN_BYTES, KYBER_CIPHERTEXT_LEN};

pub fn message_limits_dict(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("min_ciphertext_hex", MIN_CIPHERTEXT_HEX)?;
    out.set_item("max_ciphertext_hex", MAX_CIPHERTEXT_HEX)?;
    out.set_item("max_frame_text", MAX_FRAME_TEXT)?;
    out.set_item("max_mentions", MAX_MENTIONS)?;
    out.set_item("mention_min_len", MENTION_MIN_LEN)?;
    out.set_item("mention_max_len", MENTION_MAX_LEN)?;
    out.set_item("client_stamp_window_secs", CLIENT_STAMP_WINDOW_SECS)?;
    Ok(out)
}

pub fn room_limits_dict(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("name_min_len", NAME_MIN_LEN)?;
    out.set_item("name_max_len", NAME_MAX_LEN)?;
    out.set_item("description_max_len", DESCRIPTION_MAX_LEN)?;
    out.set_item("avatar_max_len", AVATAR_MAX_LEN)?;
    out.set_item("allowed_reactions_max_len", ALLOWED_REACTIONS_MAX_LEN)?;
    out.set_item("default_max_members", DEFAULT_MAX_MEMBERS)?;
    Ok(out)
}

pub fn wrapped_key_limits_dict(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("ciphertext_min_hex", CIPHERTEXT_MIN_BYTES * 2)?;
    out.set_item("kyber_ciphertext_hex_len", KYBER_CIPHERTEXT_LEN * 2)?;
    Ok(out)
}
