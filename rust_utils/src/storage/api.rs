use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use vortex_storage::config::dsn::PgConfig;
use vortex_storage::error::StorageError;
use vortex_storage::prekey::bundle::postgres::reader::PgBundleReader;
use vortex_storage::prekey::bundle::postgres::writer::PgBundleWriter;
use vortex_storage::prekey::bundle::reader::BundleReader;
use vortex_storage::prekey::bundle::writer::{BundleWriter, SaveOutcome};
use vortex_storage::prekey::device::directory::DeviceDirectory;
use vortex_storage::prekey::device::postgres::PgDeviceDirectory;
use vortex_storage::prekey::one_time::key::OneTimeKey;
use vortex_storage::prekey::one_time::keys::OneTimeKeys;
use vortex_storage::prekey::one_time::postgres::classic::PgClassicKeys;
use vortex_storage::prekey::one_time::postgres::kyber::PgKyberKeys;
use vortex_storage::time::stamp::Stamp;

use crate::proto::stored::PyStoredBundle;
use crate::storage::record::PyBundleRecord;
use crate::storage::runtime;
use crate::storage::shared;

pub fn to_py_error(error: StorageError) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}

pub fn stamp(seconds: i64, micros: u32) -> PyResult<Stamp> {
    Stamp::from_unix(seconds, micros).map_err(to_py_error)
}

fn pool(kyber: bool) -> PyResult<Box<dyn OneTimeKeys>> {
    let handle = shared::handle().map_err(to_py_error)?;
    if kyber {
        Ok(Box::new(PgKyberKeys::new(handle)))
    } else {
        Ok(Box::new(PgClassicKeys::new(handle)))
    }
}

#[pyfunction]
#[pyo3(signature = (url, pool_size=None))]
pub fn storage_connect_postgres(
    py: Python<'_>,
    url: &str,
    pool_size: Option<u32>,
) -> PyResult<bool> {
    let mut config = PgConfig::new(url);
    if let Some(size) = pool_size {
        config = config.pool_size(size);
    }
    match py.allow_threads(|| shared::connect(config)) {
        Ok(()) => Ok(true),
        Err(StorageError::Unconfigured) => Ok(false),
        Err(error) => Err(to_py_error(error)),
    }
}

#[pyfunction]
pub fn storage_is_connected() -> bool {
    shared::is_connected()
}

#[pyfunction]
pub fn storage_newest_bundle(py: Python<'_>, user_id: i64) -> PyResult<Option<PyBundleRecord>> {
    let reader = PgBundleReader::new(shared::handle().map_err(to_py_error)?);
    let found = py
        .allow_threads(|| runtime::block_on(reader.newest_of_user(user_id)))
        .map_err(to_py_error)?;
    Ok(found.map(PyBundleRecord::new))
}

#[pyfunction]
#[pyo3(signature = (user_id, device_id=None))]
pub fn storage_bundle_of_device(
    py: Python<'_>,
    user_id: i64,
    device_id: Option<i64>,
) -> PyResult<Option<PyBundleRecord>> {
    let reader = PgBundleReader::new(shared::handle().map_err(to_py_error)?);
    let found = py
        .allow_threads(|| runtime::block_on(reader.of_device(user_id, device_id)))
        .map_err(to_py_error)?;
    Ok(found.map(PyBundleRecord::new))
}

#[pyfunction]
pub fn storage_all_bundles(py: Python<'_>, user_id: i64) -> PyResult<Vec<PyBundleRecord>> {
    let reader = PgBundleReader::new(shared::handle().map_err(to_py_error)?);
    let found = py
        .allow_threads(|| runtime::block_on(reader.all_of_user(user_id)))
        .map_err(to_py_error)?;
    Ok(found.into_iter().map(PyBundleRecord::new).collect())
}

#[pyfunction]
pub fn storage_save_bundle(
    py: Python<'_>,
    user_id: i64,
    bundle: &PyStoredBundle,
    seconds: i64,
    micros: u32,
) -> PyResult<(i64, bool)> {
    let writer = PgBundleWriter::new(shared::handle().map_err(to_py_error)?);
    let at = stamp(seconds, micros)?;
    let inner = bundle.inner.clone();
    let outcome = py
        .allow_threads(|| runtime::block_on(writer.save(user_id, &inner, at)))
        .map_err(to_py_error)?;
    Ok(match outcome {
        SaveOutcome::Created(id) => (id, true),
        SaveOutcome::Updated(id) => (id, false),
    })
}

#[pyfunction]
#[pyo3(signature = (user_id, device_id, keys, seconds, micros, kyber=false))]
pub fn storage_add_one_time_keys(
    py: Python<'_>,
    user_id: i64,
    device_id: Option<i64>,
    keys: Vec<(i64, Vec<u8>)>,
    seconds: i64,
    micros: u32,
    kyber: bool,
) -> PyResult<u64> {
    let pool = pool(kyber)?;
    let at = stamp(seconds, micros)?;
    let batch: Vec<OneTimeKey> = keys
        .into_iter()
        .map(|(key_id, public_key)| OneTimeKey::new(key_id, public_key))
        .collect();
    py.allow_threads(|| runtime::block_on(pool.add_many(user_id, device_id, &batch, at)))
        .map_err(to_py_error)
}

#[pyfunction]
#[pyo3(signature = (user_id, device_id=None, kyber=false))]
pub fn storage_take_one_time_key(
    py: Python<'_>,
    user_id: i64,
    device_id: Option<i64>,
    kyber: bool,
) -> PyResult<Option<(i64, Vec<u8>)>> {
    let pool = pool(kyber)?;
    let taken = py
        .allow_threads(|| runtime::block_on(pool.take_one(user_id, device_id)))
        .map_err(to_py_error)?;
    Ok(taken.map(|key| (key.key_id, key.public_key)))
}

#[pyfunction]
#[pyo3(signature = (user_id, device_id=None, kyber=false))]
pub fn storage_available_one_time_keys(
    py: Python<'_>,
    user_id: i64,
    device_id: Option<i64>,
    kyber: bool,
) -> PyResult<i64> {
    let pool = pool(kyber)?;
    py.allow_threads(|| runtime::block_on(pool.available(user_id, device_id)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_device_of(
    py: Python<'_>,
    user_id: i64,
    client_device_id: &str,
) -> PyResult<Option<i64>> {
    let directory = PgDeviceDirectory::new(shared::handle().map_err(to_py_error)?);
    let owned = client_device_id.to_string();
    py.allow_threads(|| runtime::block_on(directory.device_of(user_id, &owned)))
        .map_err(to_py_error)
}
