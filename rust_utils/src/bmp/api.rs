use std::collections::HashMap;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use vortex_bmp::config::maintenance::MaintenanceConfig;
use vortex_bmp::derive::jitter::pair_jitter;
use vortex_bmp::derive::mailbox_id::{mailbox_id_at, mailbox_ids_at};
use vortex_bmp::error::BmpError;
use vortex_bmp::mailbox::bucket::bucket;
use vortex_bmp::mailbox::id::MailboxId;
use vortex_bmp::ratelimit::class::RateClass;
use vortex_bmp::secret::value::BmpSecret;
use vortex_bmp::service::outcome::EnvelopeOutcome;
use vortex_bmp::wake::category::wake_category;

use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::bmp::batch::PyBmpBatch;
use crate::bmp::maintenance;
use crate::bmp::rejection::PyBmpRejection;
use crate::bmp::shared;
use crate::bmp::shared::service;

fn to_py_error(error: BmpError) -> PyErr {
    PyValueError::new_err(error.to_string())
}

fn parse_secret(secret_hex: &str) -> PyResult<BmpSecret> {
    BmpSecret::parse(secret_hex).map_err(to_py_error)
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[pyfunction]
#[pyo3(signature = (url, pool_size=None, key_prefix=None))]
pub fn bmp_connect_redis(
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
pub fn bmp_is_shared() -> bool {
    shared::is_shared()
}

#[pyfunction]
pub fn bmp_deposit(
    py: Python<'_>,
    mailbox_id: &str,
    ciphertext: &str,
    client: &str,
) -> Option<PyBmpRejection> {
    py.allow_threads(|| service().deposit(mailbox_id, ciphertext, client))
        .map(PyBmpRejection::new)
}

#[pyfunction]
#[pyo3(signature = (mailbox_ids, since, client, fast=false))]
pub fn bmp_fetch_batch(
    py: Python<'_>,
    mailbox_ids: Vec<String>,
    since: f64,
    client: &str,
    fast: bool,
) -> PyResult<PyBmpBatch> {
    let class = if fast {
        RateClass::Fast
    } else {
        RateClass::Standard
    };
    match py.allow_threads(|| service().fetch_batch(&mailbox_ids, since, client, class)) {
        Ok(outcome) => PyBmpBatch::delivered(py, outcome),
        Err(rejection) => PyBmpBatch::rejected(py, PyBmpRejection::new(rejection)),
    }
}

#[pyfunction]
pub fn bmp_gc(py: Python<'_>) -> u64 {
    py.allow_threads(|| service().collect_garbage())
}

#[pyfunction]
pub fn bmp_stats(py: Python<'_>) -> HashMap<String, u64> {
    let service = service();
    let stats = py.allow_threads(|| service.stats());
    let storage = service.storage();

    let mut out = HashMap::new();
    out.insert(
        "active_mailboxes".to_string(),
        stats.active_mailboxes as u64,
    );
    out.insert("total_messages".to_string(), stats.total_messages as u64);
    out.insert("total_deposited".to_string(), stats.total_deposited);
    out.insert("total_fetched".to_string(), stats.total_fetched);
    out.insert("total_expired".to_string(), stats.total_expired);
    out.insert("ttl_seconds".to_string(), storage.ttl_secs as u64);
    out.insert("max_batch".to_string(), storage.max_batch as u64);
    out
}

#[pyfunction]
pub fn bmp_set_room_secret(
    py: Python<'_>,
    room_id: i64,
    secret_hex: &str,
) -> Option<PyBmpRejection> {
    py.allow_threads(|| service().register_room_secret(room_id, secret_hex))
        .map(PyBmpRejection::new)
}

#[pyfunction]
pub fn bmp_get_room_secret(py: Python<'_>, room_id: i64) -> Option<String> {
    py.allow_threads(|| service().room_secret(room_id))
}

#[pyfunction]
pub fn bmp_remove_room_secret(py: Python<'_>, room_id: i64) {
    py.allow_threads(|| service().forget_room_secret(room_id));
}

#[pyfunction]
pub fn bmp_deposit_envelope(py: Python<'_>, room_id: i64, envelope: &str) -> bool {
    match py.allow_threads(|| service().deposit_envelope(room_id, envelope)) {
        EnvelopeOutcome::Deposited {
            mailboxes,
            wake_categories,
        } => {
            log::debug!(
                "BMP: конверт положен в {} ящиков, категории пробуждения {:?}",
                mailboxes.len(),
                wake_categories
            );
            true
        }
        EnvelopeOutcome::UnknownRoom => {
            log::debug!("BMP: секрет комнаты {room_id} не зарегистрирован, конверт не положен");
            false
        }
        EnvelopeOutcome::Refused(refusal) => {
            log::warn!("BMP: хранилище отказало в приёме конверта — {refusal:?}");
            false
        }
    }
}

#[pyfunction]
pub fn bmp_start_gc() -> bool {
    maintenance::start(service(), MaintenanceConfig::default())
}

#[pyfunction]
#[pyo3(signature = (secret_hex, timestamp=None))]
pub fn bmp_compute_mailbox_id(secret_hex: &str, timestamp: Option<f64>) -> PyResult<String> {
    let secret = parse_secret(secret_hex)?;
    let id = mailbox_id_at(&secret, service().rotation(), timestamp.unwrap_or_else(now));
    Ok(id.into_string())
}

#[pyfunction]
#[pyo3(signature = (secret_hex, timestamp=None))]
pub fn bmp_compute_mailbox_ids(secret_hex: &str, timestamp: Option<f64>) -> PyResult<Vec<String>> {
    let secret = parse_secret(secret_hex)?;
    let ids = mailbox_ids_at(&secret, service().rotation(), timestamp.unwrap_or_else(now));
    Ok(ids.into_iter().map(MailboxId::into_string).collect())
}

#[pyfunction]
pub fn bmp_pair_jitter(secret_hex: &str) -> PyResult<u16> {
    let secret = parse_secret(secret_hex)?;
    Ok(pair_jitter(&secret, service().rotation().jitter_secs))
}

#[pyfunction]
pub fn bmp_bucket_timestamp(timestamp: f64) -> f64 {
    bucket(timestamp, service().storage().bucket_secs)
}

#[pyfunction]
pub fn bmp_wake_category(mailbox_id: &str) -> PyResult<u8> {
    let mailbox = MailboxId::parse(mailbox_id).map_err(to_py_error)?;
    Ok(wake_category(&mailbox))
}
