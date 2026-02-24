use pyo3::prelude::*;
use pyo3::types::PyBytes;
use blake3;
use aes_gcm::{
    aead::{
        Aead,
        AeadCore,
        KeyInit,
        OsRng
    },
    Aes256Gcm,
    Nonce,
    Key,
};

/// Хэширование сообщений
#[pyfunction]
fn hash_message<'py>(py: Python<'py>, message: &Bound<'_, PyBytes>) -> PyResult<Bound<'py, PyBytes>> {
    let hash = blake3::hash(message.as_bytes());
    Ok(PyBytes::new(py, hash.as_bytes()))
}

/// Генерация случайного ключа
#[pyfunction]
fn generate_key<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    Ok(PyBytes::new(py, &key))
}

/// Шифрование AES-256-GCM
#[pyfunction]
fn encrypt_message<'py>(py: Python<'py>, message: &Bound<'_, PyBytes>, key: &Bound<'py, PyBytes>) -> PyResult<Bound<'py, PyBytes>> {
    if key.as_bytes().len() != 32 {
        return Err(pyo3::exceptions::PyKeyError::new_err(
            "Key must be 32 bytes long"
        ).into())
    }

    let key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let cipher_text = cipher
        .encrypt(&nonce, message.as_bytes())
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Encryption failed"))?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&cipher_text);
    Ok(PyBytes::new(py, &result))

}

/// Дешифровка
#[pyfunction]
fn decrypt_message<'py>(py: Python<'py>, encrypted: &Bound<'_, PyBytes>, key: &Bound<'_, PyBytes>) -> PyResult<Bound<'py, PyBytes>> {
    if encrypted.as_bytes().len() < 12 + 16 + 1 {
       return Err(pyo3::exceptions::PyKeyError::new_err(
           "Encrypted data too short"
       ).into());
    }

    if key.as_bytes().len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Key must be 32 bytes long"
        ).into());
    }

    let (nonce_bytes, cipher_text) = encrypted.as_bytes().split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let plain_text = cipher
        .decrypt(nonce, cipher_text)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err(
            "Decryption failed or integrity check failed"
        ))?;

    Ok(PyBytes::new(py, &plain_text))

}

/// Класс для отслеживания сообщений
#[pyclass]
struct ChatStats {
    message_count: u64,
    bytes_processed: u64,
}

#[pymethods]
impl ChatStats {
    #[new]
    fn new() -> Self {
        ChatStats {
            message_count: 0,
            bytes_processed: 0,
        }
    }

    fn add_message(&mut self, size: usize) {
        self.message_count += 1;
        self.bytes_processed += size as u64;
    }

    fn get_stats(&self) -> String {
        format!("📊 Сообщений: {}, обработано: {} KB",
                self.message_count,
                self.bytes_processed / 1024)
    }
}

/// Регистрируем модуль
#[pymodule]
fn vortex_chat(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hash_message, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_message, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_message, m)?)?;
    m.add_class::<ChatStats>()?;
    m.add("VERSION", env!("CARGO_PKG_VERSION"))?;
    m.add("KEY_SIZE", 32)?;
    m.add("NONCE_SIZE", 12)?;
    Ok(())
}