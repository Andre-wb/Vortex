use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use std::convert::TryInto;
use x25519_dalek::{PublicKey, StaticSecret};

#[pyfunction]
pub fn generate_keypair() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);

    Ok((private.to_bytes().to_vec(), public.to_bytes().to_vec()))
}

#[pyfunction]
pub fn derive_session_key(private: Vec<u8>, peer_public: Vec<u8>) -> PyResult<Vec<u8>> {
    if private.len() != 32 || peer_public.len() != 32 {
        return Err(PyValueError::new_err(
            "Некорректная длина ключа (должно быть 32)",
        ));
    }

    let private_bytes: [u8; 32] = private
        .try_into()
        .map_err(|_| PyValueError::new_err("Некорректный формат приватного ключа"))?;

    let public_bytes: [u8; 32] = peer_public
        .try_into()
        .map_err(|_| PyValueError::new_err("Некорректный формат публичного ключа"))?;

    let private = StaticSecret::from(private_bytes);
    let peer_public_key = PublicKey::from(public_bytes);

    let shared = private.diffie_hellman(&peer_public_key);

    // Salt = sorted concatenation of both public keys. MUST match the Python
    // implementation (app/security/crypto.py::_py_derive_session_key); otherwise
    // a Rust node and a Python-fallback node derive different session keys and
    // E2E silently breaks between them.
    let local_public = PublicKey::from(&private).to_bytes();
    let mut pair = [local_public, public_bytes];
    pair.sort();
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&pair[0]);
    salt.extend_from_slice(&pair[1]);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut okm = [0u8; 32];

    hk.expand(b"vortex-session", &mut okm)
        .map_err(|_| PyValueError::new_err("HKDF расширение не удалось"))?;

    Ok(okm.to_vec())
}
