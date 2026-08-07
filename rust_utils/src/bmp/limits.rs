use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_bmp::mailbox::id::{MAX_LEN, MIN_LEN};
use vortex_bmp::secret::value::SECRET_LEN;

use crate::bmp::shared::service;

pub fn limits_dict(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let service = service();
    let storage = service.storage();
    let rate = service.rate();
    let rotation = service.rotation();

    let out = PyDict::new(py);
    out.set_item("min_ciphertext_chars", storage.min_ciphertext_chars)?;
    out.set_item("max_message_bytes", storage.max_message_bytes)?;
    out.set_item("max_ciphertext_chars", storage.max_ciphertext_chars())?;
    out.set_item("max_messages_per_mailbox", storage.max_messages_per_mailbox)?;
    out.set_item("max_mailboxes", storage.max_mailboxes)?;
    out.set_item("max_stored_bytes", storage.max_stored_bytes)?;
    out.set_item("ttl_seconds", storage.ttl_secs)?;
    out.set_item("bucket_seconds", storage.bucket_secs)?;
    out.set_item("max_batch", storage.max_batch)?;
    out.set_item("mailbox_id_min_len", MIN_LEN)?;
    out.set_item("mailbox_id_max_len", MAX_LEN)?;
    out.set_item("secret_hex_len", SECRET_LEN * 2)?;
    out.set_item("rate_window_seconds", rate.window_secs)?;
    out.set_item("standard_rate_per_window", rate.standard_per_window)?;
    out.set_item("fast_rate_per_window", rate.fast_per_window)?;
    out.set_item("rotation_period_seconds", rotation.period_secs)?;
    out.set_item("rotation_jitter_seconds", rotation.jitter_secs)?;
    out.set_item("clock_skew_epochs", rotation.clock_skew_epochs)?;
    Ok(out)
}
