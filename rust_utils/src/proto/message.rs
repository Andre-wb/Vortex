use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_proto::message::frame::content::{DigestClaim, MessageContent};
use vortex_proto::message::frame::delete::DeleteFrame;
use vortex_proto::message::frame::edit::EditFrame;
use vortex_proto::message::frame::incoming::IncomingFrame;
use vortex_proto::message::frame::send::SendFrame;
use vortex_proto::message::frame::thread_reply::ThreadReplyFrame;
use vortex_proto::message::refusal::MessageRefusal;
use vortex_proto::message::relay::error::ErrorFrame;
use vortex_proto::message::time::client_stamp::MICROS_PER_SECOND;

pub const ACTION_SEND: &str = "message";
pub const ACTION_THREAD_REPLY: &str = "thread_reply";
pub const ACTION_EDIT: &str = "edit_message";
pub const ACTION_DELETE: &str = "delete_message";

#[pyclass(module = "vortex_chat", name = "MessageRefusal", frozen)]
#[derive(Clone)]
pub struct PyMessageRefusal {
    #[pyo3(get)]
    pub message: String,
    #[pyo3(get)]
    pub code: String,
}

#[pymethods]
impl PyMessageRefusal {
    fn frame<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let out = PyDict::new(py);
        out.set_item("type", "error")?;
        out.set_item("message", &self.message)?;
        out.set_item("code", &self.code)?;
        Ok(out)
    }

    fn __repr__(&self) -> String {
        format!("<MessageRefusal code={}>", self.code)
    }
}

impl PyMessageRefusal {
    fn of(refusal: MessageRefusal) -> Self {
        let frame = ErrorFrame::of(refusal);
        PyMessageRefusal {
            message: frame.message.to_string(),
            code: frame.code.to_string(),
        }
    }
}

#[pyclass(module = "vortex_chat", name = "IncomingMessage", frozen)]
#[derive(Default)]
pub struct PyIncomingMessage {
    #[pyo3(get)]
    pub refusal: Option<PyMessageRefusal>,
    #[pyo3(get)]
    pub client_msg_id: String,
    #[pyo3(get)]
    pub ciphertext: String,
    #[pyo3(get)]
    pub content: Vec<u8>,
    #[pyo3(get)]
    pub digest: Vec<u8>,
    #[pyo3(get)]
    pub digest_hex: String,
    #[pyo3(get)]
    pub digest_claim: String,
    #[pyo3(get)]
    pub enc_v: Option<u8>,
    #[pyo3(get)]
    pub reply_to_id: Option<i64>,
    #[pyo3(get)]
    pub reply_quote: Option<String>,
    #[pyo3(get)]
    pub mentions: Vec<String>,
    #[pyo3(get)]
    pub client_ts_us: Option<i64>,
    #[pyo3(get)]
    pub msg_id: Option<i64>,
    #[pyo3(get)]
    pub thread_id: Option<i64>,
}

#[pymethods]
impl PyIncomingMessage {
    #[getter]
    fn accepted(&self) -> bool {
        self.refusal.is_none()
    }

    fn __repr__(&self) -> String {
        match &self.refusal {
            Some(refusal) => format!("<IncomingMessage refused={}>", refusal.code),
            None => format!("<IncomingMessage bytes={}>", self.content.len()),
        }
    }
}

impl PyIncomingMessage {
    fn refused(refusal: MessageRefusal) -> Self {
        PyIncomingMessage {
            refusal: Some(PyMessageRefusal::of(refusal)),
            ..PyIncomingMessage::default()
        }
    }

    fn with_content(content: &MessageContent) -> Self {
        PyIncomingMessage {
            ciphertext: content.ciphertext.to_hex(),
            content: content.ciphertext.as_bytes().to_vec(),
            digest: content.digest.as_bytes().to_vec(),
            digest_hex: content.digest.to_hex(),
            digest_claim: claim_name(content.digest_claim).to_string(),
            enc_v: content.enc_version.map(|version| version.value()),
            ..PyIncomingMessage::default()
        }
    }

    fn with_send(frame: &SendFrame) -> Self {
        PyIncomingMessage {
            client_msg_id: frame.client_msg_id.clone(),
            reply_to_id: frame.reply_to.map(|id| id.value()),
            reply_quote: frame.reply_quote.clone(),
            mentions: frame.mentions.names(),
            client_ts_us: frame.client_stamp,
            ..PyIncomingMessage::with_content(&frame.content)
        }
    }
}

fn claim_name(claim: DigestClaim) -> &'static str {
    match claim {
        DigestClaim::Absent => "absent",
        DigestClaim::Truthful => "truthful",
        DigestClaim::Untruthful => "untruthful",
    }
}

#[pyfunction]
pub fn message_read(payload: &str, action: &str, now_us: i64) -> PyIncomingMessage {
    let Some(frame) = IncomingFrame::from_json(payload) else {
        return PyIncomingMessage::refused(MessageRefusal::CiphertextMissing);
    };
    match action {
        ACTION_SEND => match SendFrame::read(&frame, now_us) {
            Ok(parsed) => PyIncomingMessage::with_send(&parsed),
            Err(refusal) => PyIncomingMessage::refused(refusal),
        },
        ACTION_THREAD_REPLY => match ThreadReplyFrame::read(&frame, now_us) {
            Ok(parsed) => PyIncomingMessage {
                thread_id: Some(parsed.thread_id.value()),
                ..PyIncomingMessage::with_send(&parsed.message)
            },
            Err(refusal) => PyIncomingMessage::refused(refusal),
        },
        ACTION_EDIT => match EditFrame::read(&frame) {
            Ok(parsed) => PyIncomingMessage {
                msg_id: Some(parsed.msg_id.value()),
                ..PyIncomingMessage::with_content(&parsed.content)
            },
            Err(refusal) => PyIncomingMessage::refused(refusal),
        },
        ACTION_DELETE => match DeleteFrame::read(&frame) {
            Ok(parsed) => PyIncomingMessage {
                msg_id: Some(parsed.msg_id.value()),
                ..PyIncomingMessage::default()
            },
            Err(refusal) => PyIncomingMessage::refused(refusal),
        },
        _ => PyIncomingMessage::refused(MessageRefusal::CiphertextMissing),
    }
}

#[pyfunction]
pub fn message_frame_too_large<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    PyMessageRefusal::of(MessageRefusal::FrameTooLarge).frame(py)
}

pub fn split_micros(microseconds: i64) -> (i64, u32) {
    (
        microseconds.div_euclid(MICROS_PER_SECOND),
        microseconds.rem_euclid(MICROS_PER_SECOND) as u32,
    )
}
