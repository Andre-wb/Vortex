use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;
use vortex_resume::cursor::cursor::Cursor;
use vortex_resume::cursor::identifier::ClientKey;
use vortex_resume::cursor::limits as cursor_limits;
use vortex_resume::error::StateError;
use vortex_resume::upload::chunk::ChunkIndex;
use vortex_resume::upload::file_name::FileName;
use vortex_resume::upload::identifier::UploadId;
use vortex_resume::upload::limits as upload_limits;
use vortex_resume::upload::lookup::{Found, Reception};
use vortex_resume::upload::plan::ChunkPlan;
use vortex_resume::upload::session::Session;

use crate::resume::shared;

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

fn upload(value: &str) -> PyResult<UploadId> {
    UploadId::parse(value).map_err(|refusal| PyValueError::new_err(refusal.to_string()))
}

fn client(value: &str) -> PyResult<ClientKey> {
    ClientKey::parse(value).map_err(|refusal| PyValueError::new_err(refusal.to_string()))
}

#[pyfunction]
#[pyo3(signature = (url, pool_size=None, key_prefix=None))]
pub fn resume_connect_redis(
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
pub fn resume_mode() -> &'static str {
    shared::mode()
}

#[pyfunction]
pub fn resume_is_shared() -> bool {
    shared::is_shared()
}

#[pyfunction]
pub fn resume_upload_limits(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let told = PyDict::new(py);
    told.set_item("default_chunk_bytes", upload_limits::DEFAULT_CHUNK_BYTES)?;
    told.set_item("min_chunk_bytes", upload_limits::MIN_CHUNK_BYTES)?;
    told.set_item("max_chunk_bytes", upload_limits::MAX_CHUNK_BYTES)?;
    told.set_item("max_chunks", upload_limits::MAX_CHUNKS)?;
    told.set_item("session_lifetime", upload_limits::SESSION_LIFETIME_SECONDS)?;
    told.set_item("max_file_name_length", upload_limits::MAX_FILE_NAME_LENGTH)?;
    told.set_item("max_cursor_rooms", cursor_limits::MAX_ROOMS)?;
    told.set_item("cursor_lifetime", cursor_limits::CURSOR_LIFETIME_SECONDS)?;
    Ok(told)
}

#[pyfunction]
pub fn resume_upload_plan(file_bytes: u64, chunk_bytes: u64) -> PyResult<(u64, u32)> {
    let plan = ChunkPlan::of(file_bytes, chunk_bytes)
        .map_err(|refusal| PyValueError::new_err(refusal.to_string()))?;
    Ok((plan.chunk_bytes(), plan.total_chunks()))
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn resume_upload_open(
    py: Python<'_>,
    upload_id: &str,
    room_id: i64,
    user_id: i64,
    file_name: &str,
    file_bytes: u64,
    total_chunks: u32,
    file_digest: &str,
) -> PyResult<()> {
    let id = upload(upload_id)?;
    let named =
        FileName::parse(file_name).map_err(|refusal| PyValueError::new_err(refusal.to_string()))?;
    let session = Session::opened(
        id,
        room(room_id)?,
        account(user_id)?,
        named,
        file_bytes,
        total_chunks,
        file_digest.to_owned(),
        shared::now(),
    );

    let resume = shared::resume();
    py.allow_threads(|| resume.uploads.open(&session))
        .map_err(unavailable)
}

#[pyfunction]
pub fn resume_upload_find<'py>(py: Python<'py>, upload_id: &str) -> PyResult<Bound<'py, PyDict>> {
    let id = upload(upload_id)?;
    let resume = shared::resume();
    let found = py
        .allow_threads(|| resume.uploads.find(&id, shared::now()))
        .map_err(unavailable)?;

    let told = PyDict::new(py);
    match found {
        Found::Live(session) => {
            told.set_item("state", "live")?;
            fill_session(&told, &session)?;
        }
        Found::Expired => told.set_item("state", "expired")?,
        Found::Missing => told.set_item("state", "missing")?,
    }
    Ok(told)
}

#[pyfunction]
pub fn resume_upload_receive<'py>(
    py: Python<'py>,
    upload_id: &str,
    chunk_index: u32,
) -> PyResult<Bound<'py, PyDict>> {
    let id = upload(upload_id)?;
    let resume = shared::resume();
    let reception = py
        .allow_threads(|| {
            resume
                .uploads
                .receive(&id, ChunkIndex::of(chunk_index), shared::now())
        })
        .map_err(unavailable)?;

    let told = PyDict::new(py);
    match reception {
        Reception::Accepted(progress) => {
            told.set_item("outcome", "accepted")?;
            fill_progress(&told, &progress)?;
        }
        Reception::AlreadyHeld(progress) => {
            told.set_item("outcome", "already_held")?;
            fill_progress(&told, &progress)?;
        }
        Reception::OutsidePlan { total } => {
            told.set_item("outcome", "outside_plan")?;
            told.set_item("total_chunks", total)?;
        }
        Reception::Expired => told.set_item("outcome", "expired")?,
        Reception::Missing => told.set_item("outcome", "missing")?,
    }
    Ok(told)
}

#[pyfunction]
pub fn resume_upload_close(py: Python<'_>, upload_id: &str) -> PyResult<bool> {
    let id = upload(upload_id)?;
    let resume = shared::resume();
    py.allow_threads(|| resume.uploads.close(&id))
        .map_err(unavailable)
}

#[pyfunction]
pub fn resume_upload_sweep(py: Python<'_>) -> PyResult<Vec<String>> {
    let resume = shared::resume();
    let swept = py
        .allow_threads(|| resume.uploads.sweep(shared::now()))
        .map_err(unavailable)?;
    Ok(swept
        .into_iter()
        .map(|id| id.written().to_owned())
        .collect())
}

#[pyfunction]
pub fn resume_upload_count(py: Python<'_>) -> PyResult<usize> {
    let resume = shared::resume();
    py.allow_threads(|| resume.uploads.count())
        .map_err(unavailable)
}

#[pyfunction]
pub fn resume_cursor_save<'py>(
    py: Python<'py>,
    user_pubkey: &str,
    last_bmp_ts: f64,
    rooms: Vec<i64>,
) -> PyResult<Bound<'py, PyDict>> {
    let key = client(user_pubkey)?;
    let resume = shared::resume();
    let cursor = py
        .allow_threads(|| resume.cursors.save(key, last_bmp_ts, &rooms, shared::now()))
        .map_err(unavailable)?;
    told_cursor(py, &cursor)
}

#[pyfunction]
pub fn resume_cursor_find<'py>(
    py: Python<'py>,
    user_pubkey: &str,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    let key = client(user_pubkey)?;
    let resume = shared::resume();
    let cursor = py
        .allow_threads(|| resume.cursors.find(&key, shared::now()))
        .map_err(unavailable)?;
    match cursor {
        Some(cursor) => Ok(Some(told_cursor(py, &cursor)?)),
        None => Ok(None),
    }
}

#[pyfunction]
pub fn resume_cursor_forget(py: Python<'_>, user_pubkey: &str) -> PyResult<bool> {
    let key = client(user_pubkey)?;
    let resume = shared::resume();
    py.allow_threads(|| resume.cursors.forget(&key))
        .map_err(unavailable)
}

#[pyfunction]
pub fn resume_cursor_count(py: Python<'_>) -> PyResult<usize> {
    let resume = shared::resume();
    py.allow_threads(|| resume.cursors.count())
        .map_err(unavailable)
}

fn fill_session(told: &Bound<'_, PyDict>, session: &Session) -> PyResult<()> {
    told.set_item("room_id", session.room().value())?;
    told.set_item("user_id", session.owner().value())?;
    told.set_item("file_name", session.file_name().written())?;
    told.set_item("file_size", session.file_bytes())?;
    told.set_item("file_hash", session.file_digest())?;
    told.set_item("opened_at", session.opened_at())?;
    told.set_item(
        "received",
        session.received().iter().copied().collect::<Vec<u32>>(),
    )?;
    fill_progress(told, &session.progress())
}

fn fill_progress(
    told: &Bound<'_, PyDict>,
    progress: &vortex_resume::upload::progress::Progress,
) -> PyResult<()> {
    told.set_item("total_chunks", progress.total())?;
    told.set_item("received_count", progress.received())?;
    told.set_item("missing", progress.missing())?;
    told.set_item("progress", progress.percent())?;
    told.set_item("complete", progress.complete())?;
    Ok(())
}

fn told_cursor<'py>(py: Python<'py>, cursor: &Cursor) -> PyResult<Bound<'py, PyDict>> {
    let told = PyDict::new(py);
    told.set_item("user_pubkey", cursor.key().written())?;
    told.set_item("last_bmp_ts", cursor.mailbox_stamp())?;
    told.set_item("rooms", cursor.rooms())?;
    told.set_item("updated_at", cursor.saved_at())?;
    Ok(told)
}
