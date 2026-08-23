use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_bmp::push::category::PushCategory;
use vortex_bmp::push::endpoint::PushEndpoint;
use vortex_bmp::push::refusal::PushStateError;
use vortex_bmp::push::registration::Registration;
use vortex_bmp::push::service::PushProxyService;
use vortex_bmp::push::token::PushToken;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::push::shared;

fn unavailable(error: PushStateError) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}

fn refused(refusal: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(refusal.to_string())
}

fn token(value: &str) -> PyResult<PushToken> {
    PushToken::parse(value).map_err(refused)
}

#[pyfunction]
#[pyo3(signature = (url, pool_size=None, key_prefix=None))]
pub fn push_connect_redis(
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
pub fn push_mode() -> &'static str {
    shared::mode()
}

#[pyfunction]
pub fn push_is_shared() -> bool {
    shared::is_shared()
}

#[pyfunction]
pub fn push_register(
    py: Python<'_>,
    categories: Vec<i64>,
    token_value: &str,
    endpoint_value: &str,
) -> PyResult<()> {
    let named = PushProxyService::categories_of(&categories).map_err(refused)?;
    let held = token(token_value)?;
    let where_to = PushEndpoint::parse(endpoint_value).map_err(refused)?;
    let proxy = shared::proxy();
    py.allow_threads(|| proxy.register(&named, held, where_to, shared::now()))
        .map_err(unavailable)
}

#[pyfunction]
pub fn push_unregister(py: Python<'_>, token_value: &str) -> PyResult<usize> {
    let held = token(token_value)?;
    let proxy = shared::proxy();
    py.allow_threads(|| proxy.unregister(&held))
        .map_err(unavailable)
}

#[pyfunction]
pub fn push_wake(py: Python<'_>, category: i64) -> PyResult<Vec<(String, String)>> {
    let named = PushCategory::wrapping(category);
    let proxy = shared::proxy();
    let woken = py
        .allow_threads(|| proxy.woken(named, shared::now()))
        .map_err(unavailable)?;
    Ok(addressed(&woken))
}

#[pyfunction]
pub fn push_registrations(py: Python<'_>, category: i64) -> PyResult<Vec<(String, String)>> {
    let named = PushCategory::wrapping(category);
    let proxy = shared::proxy();
    let held = py
        .allow_threads(|| proxy.registrations(named, shared::now()))
        .map_err(unavailable)?;
    Ok(addressed(&held))
}

#[pyfunction]
pub fn push_tally(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let proxy = shared::proxy();
    let counted = py.allow_threads(|| proxy.tally()).map_err(unavailable)?;
    let told = PyDict::new(py);
    told.set_item("total_tokens", counted.tokens())?;
    told.set_item("active_categories", counted.categories())?;
    told.set_item("total_wakes", counted.wakes())?;
    Ok(told)
}

fn addressed(held: &[Registration]) -> Vec<(String, String)> {
    held.iter()
        .map(|made| {
            (
                made.endpoint().written().to_owned(),
                made.token().written().to_owned(),
            )
        })
        .collect()
}
