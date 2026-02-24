use pyo3::prelude::*;
use pyo3::types::PyBytes;
use blake3;
use aes_gcm::{
    aead::{
        KeyInit,
        OsRng
    },
    Aes256Gcm,
};

/// Хэширование сообщений
#[pyfunction]
pub fn hash_message<'py>(py: Python<'py>, message: &Bound<'_, PyBytes>) -> PyResult<Bound<'py, PyBytes>> {
    let hash = blake3::hash(message.as_bytes());
    Ok(PyBytes::new(py, hash.as_bytes()))
}

/// Генерация случайного ключа
#[pyfunction]
pub fn generate_key<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    Ok(PyBytes::new(py, &key))
}