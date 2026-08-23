use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_proto::message::enc_version::EncVersion;
use vortex_proto::message::frame::incoming::IncomingFrame;
use vortex_proto::message::relay::ack::Ack;
use vortex_proto::message::relay::deleted::{DeletedMessage, ThreadUpdate};
use vortex_proto::message::relay::edited::EditedMessage;
use vortex_proto::message::relay::sender::Sender;
use vortex_proto::message::relay::sent::{SentMessage, SentMessageDraft};
use vortex_proto::message::relay::stored::{StoredMessage, StoredMessageDraft};
use vortex_proto::message::relay::thread_sent::{ThreadMessage, ThreadMessageDraft};
use vortex_proto::message::time::client_stamp::ClientStamp;
use vortex_proto::message::time::wire_stamp::wire_stamp;

use crate::proto::message::split_micros;

#[pyfunction]
pub fn message_wire_stamp(microseconds: i64) -> String {
    wire_stamp(split_micros(microseconds).0)
}

#[pyfunction]
pub fn message_client_stamp(text: &str, now_us: i64) -> Option<i64> {
    ClientStamp::within_window(text, now_us)
}

#[pyfunction]
pub fn message_enc_version(payload: &str) -> Option<u8> {
    let frame = IncomingFrame::from_json(payload)?;
    EncVersion::read(frame.field("enc_v")).map(|version| version.value())
}

#[pyfunction]
pub fn message_ack<'py>(
    py: Python<'py>,
    client_msg_id: &str,
    server_id: i64,
    created_at_us: i64,
) -> PyResult<Bound<'py, PyDict>> {
    ack_dict(
        py,
        &Ack::stored(client_msg_id, server_id, split_micros(created_at_us).0),
    )
}

#[pyfunction]
pub fn message_ack_duplicate<'py>(
    py: Python<'py>,
    client_msg_id: &str,
) -> PyResult<Bound<'py, PyDict>> {
    ack_dict(py, &Ack::duplicate(client_msg_id))
}

fn ack_dict<'py>(py: Python<'py>, ack: &Ack) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("type", "ack")?;
    out.set_item("msg_id", &ack.client_msg_id)?;
    if ack.duplicate {
        out.set_item("duplicate", true)?;
    } else {
        out.set_item("server_id", ack.server_id)?;
        out.set_item("created_at", &ack.created_at)?;
    }
    Ok(out)
}

#[pyfunction]
#[pyo3(signature = (
    msg_id,
    client_msg_id,
    ciphertext,
    digest_hex,
    created_at_us,
    sender_id=None,
    sender_pseudo=None,
    sender=None,
    display_name=None,
    avatar_emoji=None,
    avatar_url=None,
    is_bot=false,
    tag=None,
    tag_color=None,
    reply_color=None,
    reply_icon=None,
    enc_v=None,
    reply_to_id=None,
    reply_quote=None,
    forwarded_from=None,
    expires_at_us=None,
))]
#[allow(clippy::too_many_arguments)]
pub fn message_sent<'py>(
    py: Python<'py>,
    msg_id: i64,
    client_msg_id: &str,
    ciphertext: &str,
    digest_hex: &str,
    created_at_us: i64,
    sender_id: Option<i64>,
    sender_pseudo: Option<&str>,
    sender: Option<&str>,
    display_name: Option<&str>,
    avatar_emoji: Option<&str>,
    avatar_url: Option<&str>,
    is_bot: bool,
    tag: Option<&str>,
    tag_color: Option<&str>,
    reply_color: Option<&str>,
    reply_icon: Option<&str>,
    enc_v: Option<u8>,
    reply_to_id: Option<i64>,
    reply_quote: Option<&str>,
    forwarded_from: Option<&str>,
    expires_at_us: Option<i64>,
) -> PyResult<Bound<'py, PyDict>> {
    let mut speaker = Sender::named(sender.unwrap_or(""), display_name);
    speaker.user_id = sender_id;
    speaker.pseudo = sender_pseudo.map(str::to_string);
    speaker.avatar_emoji = avatar_emoji.map(str::to_string);
    speaker.avatar_url = avatar_url.map(str::to_string);
    speaker.is_bot = is_bot;
    speaker.tag = tag.map(str::to_string);
    speaker.tag_color = tag_color.map(str::to_string);
    speaker.reply_color = reply_color.map(str::to_string);
    speaker.reply_icon = reply_icon.map(str::to_string);

    let message = SentMessage::render(SentMessageDraft {
        msg_id,
        client_msg_id,
        sender: speaker,
        ciphertext,
        hash: digest_hex,
        enc_v,
        reply_to_id,
        reply_quote,
        forwarded_from,
        expires_at: expires_at_us.map(|value| split_micros(value).0),
        created_at: split_micros(created_at_us).0,
    });

    let out = PyDict::new(py);
    out.set_item("type", "message")?;
    out.set_item("msg_id", message.msg_id)?;
    out.set_item("client_msg_id", &message.client_msg_id)?;
    out.set_item("sender_id", message.sender.user_id)?;
    out.set_item("sender_pseudo", &message.sender.pseudo)?;
    out.set_item("sender", &message.sender.username)?;
    out.set_item("display_name", message.sender.shown_name())?;
    out.set_item("avatar_emoji", &message.sender.avatar_emoji)?;
    out.set_item("avatar_url", &message.sender.avatar_url)?;
    out.set_item("is_bot", message.sender.is_bot)?;
    out.set_item("tag", &message.sender.tag)?;
    out.set_item("tag_color", &message.sender.tag_color)?;
    out.set_item("reply_color", &message.sender.reply_color)?;
    out.set_item("reply_icon", &message.sender.reply_icon)?;
    out.set_item("ciphertext", &message.ciphertext)?;
    out.set_item("hash", &message.hash)?;
    out.set_item("enc_v", message.enc_v)?;
    out.set_item("reply_to_id", message.reply_to_id)?;
    out.set_item("reply_quote", &message.reply_quote)?;
    out.set_item("status", message.status)?;
    out.set_item("forwarded_from", &message.forwarded_from)?;
    out.set_item("expires_at", &message.expires_at)?;
    out.set_item("created_at", &message.created_at)?;
    Ok(out)
}

#[pyfunction]
#[pyo3(signature = (
    msg_id,
    client_msg_id,
    thread_id,
    ciphertext,
    digest_hex,
    created_at_us,
    sender_pseudo=None,
    sender=None,
    display_name=None,
    avatar_emoji=None,
    avatar_url=None,
    enc_v=None,
    reply_to_id=None,
    reply_quote=None,
))]
#[allow(clippy::too_many_arguments)]
pub fn message_thread_sent<'py>(
    py: Python<'py>,
    msg_id: i64,
    client_msg_id: &str,
    thread_id: i64,
    ciphertext: &str,
    digest_hex: &str,
    created_at_us: i64,
    sender_pseudo: Option<&str>,
    sender: Option<&str>,
    display_name: Option<&str>,
    avatar_emoji: Option<&str>,
    avatar_url: Option<&str>,
    enc_v: Option<u8>,
    reply_to_id: Option<i64>,
    reply_quote: Option<&str>,
) -> PyResult<Bound<'py, PyDict>> {
    let mut speaker = Sender::named(sender.unwrap_or(""), display_name);
    speaker.pseudo = sender_pseudo.map(str::to_string);
    speaker.avatar_emoji = avatar_emoji.map(str::to_string);
    speaker.avatar_url = avatar_url.map(str::to_string);

    let message = ThreadMessage::render(ThreadMessageDraft {
        msg_id,
        client_msg_id,
        thread_id,
        sender: speaker,
        ciphertext,
        hash: digest_hex,
        enc_v,
        reply_to_id,
        reply_quote,
        created_at: split_micros(created_at_us).0,
    });

    let out = PyDict::new(py);
    out.set_item("type", "thread_message")?;
    out.set_item("msg_id", message.msg_id)?;
    out.set_item("client_msg_id", &message.client_msg_id)?;
    out.set_item("sender_pseudo", &message.sender.pseudo)?;
    out.set_item("sender", &message.sender.username)?;
    out.set_item("display_name", message.sender.shown_name())?;
    out.set_item("avatar_emoji", &message.sender.avatar_emoji)?;
    out.set_item("avatar_url", &message.sender.avatar_url)?;
    out.set_item("ciphertext", &message.ciphertext)?;
    out.set_item("hash", &message.hash)?;
    out.set_item("enc_v", message.enc_v)?;
    out.set_item("reply_to_id", message.reply_to_id)?;
    out.set_item("reply_quote", &message.reply_quote)?;
    out.set_item("thread_id", message.thread_id)?;
    out.set_item("status", message.status)?;
    out.set_item("created_at", &message.created_at)?;
    Ok(out)
}

#[pyfunction]
#[pyo3(signature = (msg_id, ciphertext, enc_v=None))]
pub fn message_edited<'py>(
    py: Python<'py>,
    msg_id: i64,
    ciphertext: &str,
    enc_v: Option<u8>,
) -> PyResult<Bound<'py, PyDict>> {
    let edited = EditedMessage::render(msg_id, ciphertext, enc_v);
    let out = PyDict::new(py);
    out.set_item("type", "message_edited")?;
    out.set_item("msg_id", edited.msg_id)?;
    out.set_item("ciphertext", &edited.ciphertext)?;
    out.set_item("enc_v", edited.enc_v)?;
    out.set_item("is_edited", edited.is_edited)?;
    Ok(out)
}

#[pyfunction]
pub fn message_deleted(py: Python<'_>, msg_id: i64) -> PyResult<Bound<'_, PyDict>> {
    let deleted = DeletedMessage::render(msg_id);
    let out = PyDict::new(py);
    out.set_item("type", "message_deleted")?;
    out.set_item("msg_id", deleted.msg_id)?;
    Ok(out)
}

#[pyfunction]
#[pyo3(signature = (msg_id, thread_count=None))]
pub fn message_thread_update(
    py: Python<'_>,
    msg_id: i64,
    thread_count: Option<i64>,
) -> PyResult<Bound<'_, PyDict>> {
    let update = ThreadUpdate::render(msg_id, thread_count);
    let out = PyDict::new(py);
    out.set_item("type", "thread_update")?;
    out.set_item("msg_id", update.msg_id)?;
    out.set_item("thread_count", update.thread_count)?;
    Ok(out)
}

#[pyfunction]
#[pyo3(signature = (
    msg_id,
    msg_type,
    created_at_us,
    sender_pseudo=None,
    content=None,
    digest=None,
    enc_v=None,
    file_name=None,
    file_size=None,
    reply_to_id=None,
    thread_id=None,
    thread_count=None,
    is_edited=None,
    forwarded_from=None,
    expires_at_us=None,
))]
#[allow(clippy::too_many_arguments)]
pub fn message_stored<'py>(
    py: Python<'py>,
    msg_id: i64,
    msg_type: &str,
    created_at_us: i64,
    sender_pseudo: Option<&str>,
    content: Option<Vec<u8>>,
    digest: Option<Vec<u8>>,
    enc_v: Option<u8>,
    file_name: Option<&str>,
    file_size: Option<i64>,
    reply_to_id: Option<i64>,
    thread_id: Option<i64>,
    thread_count: Option<i64>,
    is_edited: Option<bool>,
    forwarded_from: Option<&str>,
    expires_at_us: Option<i64>,
) -> PyResult<Bound<'py, PyDict>> {
    let stored = StoredMessage::render(StoredMessageDraft {
        msg_id,
        sender_pseudo,
        msg_type,
        content: content.as_deref(),
        digest: digest.as_deref(),
        enc_v,
        file_name,
        file_size,
        reply_to_id,
        thread_id,
        thread_count,
        is_edited,
        forwarded_from,
        expires_at: expires_at_us.map(split_micros),
        created_at: split_micros(created_at_us),
    });

    let out = PyDict::new(py);
    out.set_item("msg_id", stored.msg_id)?;
    out.set_item("sender_pseudo", &stored.sender_pseudo)?;
    out.set_item("msg_type", &stored.msg_type)?;
    out.set_item("ciphertext", &stored.ciphertext)?;
    out.set_item("hash", &stored.hash)?;
    out.set_item("enc_v", stored.enc_v)?;
    out.set_item("file_name", &stored.file_name)?;
    out.set_item("file_size", stored.file_size)?;
    out.set_item("reply_to_id", stored.reply_to_id)?;
    out.set_item("thread_id", stored.thread_id)?;
    out.set_item("thread_count", stored.thread_count)?;
    out.set_item("is_edited", stored.is_edited)?;
    out.set_item("forwarded_from", &stored.forwarded_from)?;
    out.set_item("expires_at", &stored.expires_at)?;
    out.set_item("created_at", &stored.created_at)?;
    Ok(out)
}
