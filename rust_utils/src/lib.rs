use pyo3::prelude::*;

mod messages;
pub use messages::{
    crypt::{decrypt_message, encrypt_message},
    hash::{generate_key, hash_message},
    ChatStats,
};

mod auth;
use auth::{
    passwords::{hash_password, verify_password},
    tokens::{hash_token, verify_token},
};

mod udp_broadcast;
use udp_broadcast::discovery::{get_peers, start_discovery};

mod crypto;
use crypto::handshake::{derive_session_key, generate_keypair};

pub mod bmp;
use bmp::api::*;
use bmp::batch::PyBmpBatch;
use bmp::limits::limits_dict;
use bmp::rejection::PyBmpRejection;

pub mod pq;
use pq::pybridge::{
    mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_encapsulate_derand, mlkem768_keygen,
    mlkem768_keygen_derand, pq_hybrid_combine,
};

mod sealed_sender;
use sealed_sender::{compute_sender_pseudo, compute_sender_pseudo_batch, verify_sender_pseudo};
mod canonical_json;
use canonical_json::{canonical_json as canonical_json_fn, sign_canonical};
mod ratchet_kdf;
use ratchet_kdf::{
    ratchet_advance_chain, ratchet_decrypt_step, ratchet_encrypt_step, ratchet_kdf_ck,
    ratchet_kdf_rk, ratchet_message_key, ratchet_root_kdf,
};
mod integrity_walk;
use integrity_walk::{sha256_manifest_walk, verify_manifest};
mod steganography;
use steganography::{steg_embed_bytes, steg_embed_png, steg_extract_png};
mod metadata_padding;
use metadata_padding::{pad_bucket_for, pad_to_bucket, unpad_from_bucket};
mod batch_verify;
use batch_verify::{batch_verify as ed_batch_verify, verify_signature as ed_verify};
mod chunk_hash;
use chunk_hash::{sha256_combine_hex, sha256_concat_hex, sha256_hex, sha256_stream};
pub mod transport;
use transport::censorship_bridge::{PyCensorshipDashboard, PyCensorshipRejection};
use transport::latency_bridge::PyLatencyMonitor;
use transport::naive_bridge::PyNaive;
use transport::obfuscation_bridge::{
    PyObfuscation, PyObfuscationFrameStep, PyObfuscationFrames, PyObfuscationSession,
    PyTrafficNormalizer,
};
use transport::probe_bridge::{PyCensorshipProbe, PyProbeTarget};
use transport::reality_bridge::PyRealityAuth;
use transport::shadowsocks_bridge::{PyShadowsocks, PyShadowsocksFrameStep, PyShadowsocksSession};
use transport::shadowtls_bridge::{
    PyShadowTls, PyShadowTlsClientStep, PyShadowTlsConnection, PyShadowTlsDonorStep,
    PyShadowTlsStream,
};
use transport::sw_bridge::PyServiceWorkerProfile;
use transport::timeout_bridge::{handshake_timeout_secs, PyReadDeadline};
use transport::trojan_bridge::{PyTrojan, PyTrojanRequest};

#[pymodule]
fn vortex_chat(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let _ = pyo3_log::Logger::default()
        .filter(log::LevelFilter::Trace)
        .install();

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

    m.add("BMP_LIMITS", limits_dict(m.py())?)?;
    m.add_class::<PyBmpRejection>()?;
    m.add_class::<PyBmpBatch>()?;
    m.add_function(wrap_pyfunction!(bmp_connect_redis, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_is_shared, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_deposit, m)?)?;
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
    m.add_function(wrap_pyfunction!(bmp_bucket_timestamp, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_wake_category, m)?)?;
    m.add_function(wrap_pyfunction!(bmp_start_gc, m)?)?;

    m.add_function(wrap_pyfunction!(compute_sender_pseudo, m)?)?;
    m.add_function(wrap_pyfunction!(verify_sender_pseudo, m)?)?;
    m.add_function(wrap_pyfunction!(compute_sender_pseudo_batch, m)?)?;

    m.add_function(wrap_pyfunction!(canonical_json_fn, m)?)?;
    m.add_function(wrap_pyfunction!(sign_canonical, m)?)?;

    m.add_function(wrap_pyfunction!(ratchet_advance_chain, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_message_key, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_encrypt_step, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_decrypt_step, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_root_kdf, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_kdf_rk, m)?)?;
    m.add_function(wrap_pyfunction!(ratchet_kdf_ck, m)?)?;

    m.add_function(wrap_pyfunction!(sha256_manifest_walk, m)?)?;
    m.add_function(wrap_pyfunction!(verify_manifest, m)?)?;

    m.add_function(wrap_pyfunction!(steg_embed_png, m)?)?;
    m.add_function(wrap_pyfunction!(steg_extract_png, m)?)?;
    m.add_function(wrap_pyfunction!(steg_embed_bytes, m)?)?;

    m.add_function(wrap_pyfunction!(pad_to_bucket, m)?)?;
    m.add_function(wrap_pyfunction!(unpad_from_bucket, m)?)?;
    m.add_function(wrap_pyfunction!(pad_bucket_for, m)?)?;

    m.add_function(wrap_pyfunction!(ed_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ed_batch_verify, m)?)?;

    m.add_function(wrap_pyfunction!(sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_concat_hex, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_combine_hex, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_stream, m)?)?;

    m.add_function(wrap_pyfunction!(mlkem768_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem768_encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem768_decapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem768_keygen_derand, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem768_encapsulate_derand, m)?)?;
    m.add_function(wrap_pyfunction!(pq_hybrid_combine, m)?)?;

    m.add_class::<PyRealityAuth>()?;
    m.add_class::<PyShadowsocks>()?;
    m.add_class::<PyShadowsocksSession>()?;
    m.add_class::<PyShadowsocksFrameStep>()?;
    m.add_class::<PyShadowTls>()?;
    m.add_class::<PyShadowTlsConnection>()?;
    m.add_class::<PyShadowTlsClientStep>()?;
    m.add_class::<PyShadowTlsDonorStep>()?;
    m.add_class::<PyShadowTlsStream>()?;
    m.add_class::<PyTrojan>()?;
    m.add_class::<PyTrojanRequest>()?;
    m.add_class::<PyNaive>()?;
    m.add_class::<PyReadDeadline>()?;
    m.add_class::<PyObfuscation>()?;
    m.add_class::<PyTrafficNormalizer>()?;
    m.add_class::<PyObfuscationFrames>()?;
    m.add_class::<PyObfuscationSession>()?;
    m.add_class::<PyObfuscationFrameStep>()?;
    m.add_class::<PyCensorshipProbe>()?;
    m.add_class::<PyProbeTarget>()?;
    m.add_class::<PyLatencyMonitor>()?;
    m.add_class::<PyCensorshipDashboard>()?;
    m.add_class::<PyCensorshipRejection>()?;
    m.add_class::<PyServiceWorkerProfile>()?;

    m.add("HANDSHAKE_TIMEOUT_SECS", handshake_timeout_secs())?;
    m.add("VERSION", env!("CARGO_PKG_VERSION"))?;
    m.add("KEY_SIZE", 32usize)?;
    m.add("NONCE_SIZE", 12usize)?;
    Ok(())
}
