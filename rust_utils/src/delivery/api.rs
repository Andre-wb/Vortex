use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;
use vortex_delivery::error::StateError;
use vortex_delivery::message::identifier::MessageId;
use vortex_delivery::message::payload::Payload;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::delivery::shared;

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

fn readers(values: &[i64]) -> PyResult<Vec<UserId>> {
    values.iter().map(|value| account(*value)).collect()
}

fn message(value: &str) -> PyResult<MessageId> {
    MessageId::parse(value).map_err(|refusal| PyValueError::new_err(refusal.to_string()))
}

#[pyfunction]
#[pyo3(signature = (url, pool_size=None, key_prefix=None))]
pub fn delivery_connect_redis(
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
pub fn delivery_mode() -> &'static str {
    shared::mode()
}

#[pyfunction]
pub fn delivery_is_shared() -> bool {
    shared::is_shared()
}

#[pyfunction]
pub fn delivery_is_repeat(py: Python<'_>, msg_id: &str) -> PyResult<bool> {
    let named = message(msg_id)?;
    let delivery = shared::delivery();
    py.allow_threads(|| delivery.dedup.is_repeat(&named, shared::now()))
        .map_err(unavailable)
}

#[pyfunction]
pub fn delivery_seen_count(py: Python<'_>) -> PyResult<usize> {
    let delivery = shared::delivery();
    py.allow_threads(|| delivery.dedup.remembered())
        .map_err(unavailable)
}

#[pyfunction]
pub fn delivery_room_deposit(
    py: Python<'_>,
    room_id: i64,
    user_ids: Vec<i64>,
    payload: &str,
) -> PyResult<()> {
    let named = room(room_id)?;
    let people = readers(&user_ids)?;
    let text = Payload::of(payload);
    let delivery = shared::delivery();
    py.allow_threads(|| delivery.rooms.deposit(named, &people, &text, shared::now()))
        .map_err(unavailable)
}

#[pyfunction]
pub fn delivery_room_collect(py: Python<'_>, room_id: i64, user_id: i64) -> PyResult<Vec<String>> {
    let named = room(room_id)?;
    let person = account(user_id)?;
    let delivery = shared::delivery();
    py.allow_threads(|| delivery.rooms.collect(named, person, shared::now()))
        .map_err(unavailable)
}

#[pyfunction]
pub fn delivery_room_sweep(py: Python<'_>) -> PyResult<usize> {
    let delivery = shared::delivery();
    py.allow_threads(|| delivery.rooms.sweep(shared::now()))
        .map_err(unavailable)
}

#[pyfunction]
pub fn delivery_room_tally(py: Python<'_>) -> PyResult<(usize, usize)> {
    let delivery = shared::delivery();
    py.allow_threads(|| delivery.rooms.tally())
        .map_err(unavailable)
}

#[pyfunction]
pub fn delivery_notification_deposit(py: Python<'_>, user_id: i64, payload: &str) -> PyResult<()> {
    let person = account(user_id)?;
    let text = Payload::of(payload);
    let delivery = shared::delivery();
    py.allow_threads(|| delivery.notifications.deposit(person, &text, shared::now()))
        .map_err(unavailable)
}

#[pyfunction]
pub fn delivery_notification_collect(py: Python<'_>, user_id: i64) -> PyResult<Vec<String>> {
    let person = account(user_id)?;
    let delivery = shared::delivery();
    py.allow_threads(|| delivery.notifications.collect(person, shared::now()))
        .map_err(unavailable)
}

#[pyfunction]
pub fn delivery_notification_tally(py: Python<'_>) -> PyResult<(usize, usize)> {
    let delivery = shared::delivery();
    py.allow_threads(|| delivery.notifications.tally())
        .map_err(unavailable)
}
