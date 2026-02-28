use pyo3::prelude::*;
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;

/// Hashing token
#[pyfunction]
pub fn hash_token(token: &str) -> PyResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

///Verifying token
/// Python using example:
/// 
/// import rust_utils
/// hashed_token = rust_utils.hash_token("token")
/// rust_utils.verify_token("token", hashed_token)
#[pyfunction]
pub fn verify_token(token: &str, expected_hash: &str) -> PyResult<bool> {
    let computed = hash_token(token)?;
    Ok(computed.as_bytes().ct_eq(expected_hash.as_bytes()).into())
}