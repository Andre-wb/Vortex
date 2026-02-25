use pyo3::prelude::*;
use pyo3::types::PyBytes;
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

/// AES-256-GCM
#[pyfunction]
pub fn encrypt_message<'py>(py: Python<'py>, message: &Bound<'_, PyBytes>, key: &Bound<'py, PyBytes>) -> PyResult<Bound<'py, PyBytes>> {
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

/// Decrypt
#[pyfunction]
pub fn decrypt_message<'py>(py: Python<'py>, encrypted: &Bound<'_, PyBytes>, key: &Bound<'_, PyBytes>) -> PyResult<Bound<'py, PyBytes>> {
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