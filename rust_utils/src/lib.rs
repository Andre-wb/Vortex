use pyo3::prelude::*;

mod messages;
pub use messages::{
    hash::{hash_message, generate_key},
    crypt::{encrypt_message, decrypt_message},
    ChatStats
};

mod auth;
use auth::{
    passwords::{hash_password, verify_password},
    tokens::{hash_token, verify_token},
};

mod udp_broadcast;
use udp_broadcast::discovery::{get_peers, start_discovery};

mod crypto;
use crypto::handshake::{
    derive_session_key, generate_keypair
};

pub mod bmp;
use bmp::pybridge::*;


#[pymodule]
fn vortex_chat(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Existing crypto
    m.add_function(wrap_pyfunction!(hash_message, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_message, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_message, m)?)?;
    m.add_function(wrap_pyfunction!(hash_password, m)?)?;
    m.add_function(wrap_pyfunction!(verify_password, m)?)?;
    m.add_function(wrap_pyfunction!(hash_token, m)?)?;
    m.add_function(wrap_pyfunction!(verify_token, m)?)?;
    m.add_function(wrap_pyfunction!(start_discovery, m)?)?;
    m.add_function(wrap_pyfunction!(get_peers, m)?)?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(derive_session_key, m)?)?;
    m.add_class::<ChatStats>()?;

    // BMP (Blind Mailbox Protocol) — high-performance Rust implementation
    m.add_function(wrap_pyfunction!(bmp_deposit, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_fetch, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_fetch_batch, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_gc, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_stats, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_compute_mailbox_id, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_compute_mailbox_ids, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_pair_jitter, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_set_room_secret, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_get_room_secret, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_remove_room_secret, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_deposit_envelope, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_check_rate, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_check_rate_fast, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_wake_category, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_start_gc, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_benchmark, m)?)?;

    m.add("VERSION", env!("CARGO_PKG_VERSION"))?;
    m.add("KEY_SIZE", 32usize)?;
    m.add("NONCE_SIZE", 12usize)?;
    Ok(())
}