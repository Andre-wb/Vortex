use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_net::registry::peer::PeerRecord;
use vortex_net::registry::refusal::RegistryError;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::registry::shared;

fn unavailable(error: RegistryError) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}

fn refused(refusal: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(refusal.to_string())
}

#[pyfunction]
#[pyo3(signature = (url, pool_size=None, key_prefix=None))]
pub fn registry_connect_redis(
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
pub fn registry_mode() -> &'static str {
    shared::mode()
}

#[pyfunction]
pub fn registry_is_shared() -> bool {
    shared::is_shared()
}

#[pyfunction]
pub fn registry_set_timeout(seconds: f64) {
    shared::set_timeout(seconds);
}

#[pyfunction]
pub fn registry_own_address() -> String {
    shared::own_address()
}

#[pyfunction]
pub fn registry_set_own_address(address: String) {
    shared::set_own_address(address);
}

#[pyfunction]
#[pyo3(signature = (address, name, port, pubkey=None))]
pub fn registry_heard(
    py: Python<'_>,
    address: &str,
    name: &str,
    port: u16,
    pubkey: Option<&str>,
) -> PyResult<bool> {
    let peers = shared::registry();
    py.allow_threads(|| peers.heard(address, name, port, pubkey, shared::now()))
        .map_err(refused)?
        .map_err(unavailable)
}

#[pyfunction]
pub fn registry_find<'py>(py: Python<'py>, address: &str) -> PyResult<Option<Bound<'py, PyDict>>> {
    let peers = shared::registry();
    let now = shared::now();
    let found = py
        .allow_threads(|| peers.find(address))
        .map_err(refused)?
        .map_err(unavailable)?;
    match found {
        Some(known) => Ok(Some(told_peer(py, &known, now)?)),
        None => Ok(None),
    }
}

#[pyfunction]
pub fn registry_alive<'py>(py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let peers = shared::registry();
    let now = shared::now();
    let living = py.allow_threads(|| peers.alive(now)).map_err(unavailable)?;
    living
        .iter()
        .map(|known| told_peer(py, known, now))
        .collect()
}

#[pyfunction]
pub fn registry_forget_dead(py: Python<'_>) -> PyResult<usize> {
    let peers = shared::registry();
    py.allow_threads(|| peers.forget_dead(shared::now()))
        .map_err(unavailable)
}

#[pyfunction]
pub fn registry_set_rooms(py: Python<'_>, address: &str, document: &str) -> PyResult<()> {
    let peers = shared::registry();
    py.allow_threads(|| peers.set_rooms(address, document))
        .map_err(refused)?
        .map_err(unavailable)
}

#[pyfunction]
pub fn registry_rooms_of_the_living(
    py: Python<'_>,
) -> PyResult<Vec<(String, String, u16, String)>> {
    let peers = shared::registry();
    let told = py
        .allow_threads(|| peers.rooms_of_the_living(shared::now()))
        .map_err(unavailable)?;
    Ok(told
        .into_iter()
        .map(|(known, document)| {
            (
                known.address().written().to_owned(),
                known.name().written().to_owned(),
                known.port(),
                document,
            )
        })
        .collect())
}

#[pyfunction]
pub fn registry_count(py: Python<'_>) -> PyResult<usize> {
    let peers = shared::registry();
    py.allow_threads(|| peers.count()).map_err(unavailable)
}

fn told_peer<'py>(py: Python<'py>, known: &PeerRecord, now: f64) -> PyResult<Bound<'py, PyDict>> {
    let told = PyDict::new(py);
    told.set_item("ip", known.address().written())?;
    told.set_item("name", known.name().written())?;
    told.set_item("port", known.port())?;
    told.set_item("pubkey", known.pubkey().map(|key| key.written()))?;
    told.set_item(
        "shortened_pubkey",
        known.pubkey().map(|key| key.shortened()),
    )?;
    told.set_item("age_sec", known.age(now))?;
    told.set_item("online", known.alive(now, shared::timeout()))?;
    told.set_item("encrypted", known.encrypted())?;
    Ok(told)
}

#[pyfunction]
pub fn registry_next_virtual_room(py: Python<'_>) -> PyResult<i64> {
    let ids = shared::virtual_rooms();
    py.allow_threads(|| ids.next())
        .map(|named| named.value())
        .map_err(unavailable)
}

#[pyfunction]
pub fn registry_reserve_virtual_room(py: Python<'_>, taken: i64) -> PyResult<()> {
    let ids = shared::virtual_rooms();
    py.allow_threads(|| ids.reserve_below(taken))
        .map_err(unavailable)
}
