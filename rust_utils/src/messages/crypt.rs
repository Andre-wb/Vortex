use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key,
    Nonce,
};

/// AES-256-GCM encryption
#[pyfunction]
pub fn encrypt_message(message: Vec<u8>, key: Vec<u8>) -> PyResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key must be 32 bytes long"));
    }

    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, message.as_ref())
        .map_err(|_| PyValueError::new_err("Encryption failed"))?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// AES-256-GCM decryption
#[pyfunction]
pub fn decrypt_message(encrypted: Vec<u8>, key: Vec<u8>) -> PyResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key must be 32 bytes long"));
    }

    if encrypted.len() < 12 {
        return Err(PyValueError::new_err("Encrypted data too short"));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| PyValueError::new_err(
            "Decryption failed or integrity check failed"
        ))?;

    Ok(plaintext)
}