use pyo3::prelude::*;

mod messages;
use messages::ChatStats;
use messages::hash::{hash_message, generate_key};
use messages::crypt::{encrypt_message, decrypt_message};

/// Регистрация модуля
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