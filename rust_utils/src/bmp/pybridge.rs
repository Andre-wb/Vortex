//! PyO3 bridge — exposes BMP functions to Python.

use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;
use pyo3::prelude::*;

use crate::bmp::gc::start_gc_thread;
use crate::bmp::mailbox_id;
use crate::bmp::rate_limit::RateLimiter;
use crate::bmp::room_secrets::RoomSecretStore;
use crate::bmp::store::BlindMailboxStore;

// Global singletons (initialized once, live for process lifetime)
static STORE: Lazy<Arc<BlindMailboxStore>> = Lazy::new(|| Arc::new(BlindMailboxStore::new()));
static SECRETS: Lazy<Arc<RoomSecretStore>> = Lazy::new(|| Arc::new(RoomSecretStore::new()));
static RATE_LIMITER: Lazy<Arc<RateLimiter>> = Lazy::new(|| Arc::new(RateLimiter::new()));

// ── Store operations ────────────────────────────────────────────────────────

#[pyfunction]
pub fn bmp_deposit(mailbox_id: &str, ciphertext: &str) -> bool {
    STORE.deposit(mailbox_id, ciphertext)
}

#[pyfunction]
pub fn bmp_fetch(mailbox_id: &str, since_ts: f64) -> Vec<(String, f64)> {
    STORE.fetch(mailbox_id, since_ts)
}

#[pyfunction]
pub fn bmp_fetch_batch(
    mailbox_ids: Vec<String>,
    since_ts: f64,
) -> HashMap<String, Vec<(String, f64)>> {
    STORE.fetch_batch(&mailbox_ids, since_ts)
}

#[pyfunction]
pub fn bmp_gc() -> u64 {
    STORE.gc()
}

#[pyfunction]
pub fn bmp_stats() -> HashMap<String, u64> {
    let s = STORE.stats();
    let mut m = HashMap::new();
    m.insert("active_mailboxes".to_string(), s.active_mailboxes as u64);
    m.insert("total_messages".to_string(), s.total_messages as u64);
    m.insert("total_deposited".to_string(), s.total_deposited);
    m.insert("total_fetched".to_string(), s.total_fetched);
    m.insert("total_expired".to_string(), s.total_expired);
    m
}

// ── Mailbox ID derivation ───────────────────────────────────────────────────

#[pyfunction]
#[pyo3(signature = (secret_hex, timestamp=None))]
pub fn bmp_compute_mailbox_id(secret_hex: &str, timestamp: Option<f64>) -> String {
    mailbox_id::compute_mailbox_id(secret_hex, timestamp)
}

#[pyfunction]
#[pyo3(signature = (secret_hex, timestamp=None))]
pub fn bmp_compute_mailbox_ids(secret_hex: &str, timestamp: Option<f64>) -> Vec<String> {
    mailbox_id::compute_mailbox_ids(secret_hex, timestamp)
}

#[pyfunction]
pub fn bmp_pair_jitter(secret_hex: &str) -> u16 {
    mailbox_id::pair_jitter(secret_hex)
}

// ── Room secrets ────────────────────────────────────────────────────────────

#[pyfunction]
pub fn bmp_set_room_secret(room_id: i64, secret_hex: &str) {
    SECRETS.set(room_id, secret_hex.to_string());
}

#[pyfunction]
pub fn bmp_get_room_secret(room_id: i64) -> Option<String> {
    SECRETS.get(room_id)
}

#[pyfunction]
pub fn bmp_remove_room_secret(room_id: i64) {
    SECRETS.remove(room_id);
}

// ── Envelope deposit (room → mailbox IDs → deposit) ─────────────────────────

#[pyfunction]
pub fn bmp_deposit_envelope(room_id: i64, envelope_data: &str) -> bool {
    STORE.deposit_envelope(room_id, envelope_data, &SECRETS)
}

// ── Rate limiting ───────────────────────────────────────────────────────────

#[pyfunction]
pub fn bmp_check_rate(ip: &str) -> bool {
    RATE_LIMITER.check_standard(ip)
}

#[pyfunction]
pub fn bmp_check_rate_fast(ip: &str) -> bool {
    RATE_LIMITER.check_fast(ip)
}

// ── Wake signal ─────────────────────────────────────────────────────────────

#[pyfunction]
pub fn bmp_wake_category(mailbox_id: &str) -> u8 {
    BlindMailboxStore::wake_category(mailbox_id)
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

#[pyfunction]
pub fn bmp_start_gc() {
    start_gc_thread(STORE.clone(), RATE_LIMITER.clone());
}

// ── Benchmark ───────────────────────────────────────────────────────────────

#[pyfunction]
pub fn bmp_benchmark() -> HashMap<String, f64> {
    use std::time::Instant;

    let store = BlindMailboxStore::new();
    let n = 100_000u64;

    // Deposit benchmark
    let start = Instant::now();
    for i in 0..n {
        store.deposit(&format!("bench_{}", i % 1000), &format!("ct_{}", i));
    }
    let deposit_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Fetch benchmark
    let start = Instant::now();
    for i in 0..n {
        store.fetch(&format!("bench_{}", i % 1000), 0.0);
    }
    let fetch_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Batch fetch benchmark
    let ids: Vec<String> = (0..100).map(|i| format!("bench_{}", i)).collect();
    let start = Instant::now();
    for _ in 0..10_000 {
        store.fetch_batch(&ids, 0.0);
    }
    let batch_ms = start.elapsed().as_secs_f64() * 1000.0;

    let mut results = HashMap::new();
    results.insert("deposit_100k_ms".to_string(), deposit_ms);
    results.insert("deposit_ops_per_sec".to_string(), n as f64 / deposit_ms * 1000.0);
    results.insert("fetch_100k_ms".to_string(), fetch_ms);
    results.insert("fetch_ops_per_sec".to_string(), n as f64 / fetch_ms * 1000.0);
    results.insert("batch_10k_ms".to_string(), batch_ms);
    results.insert("batch_ops_per_sec".to_string(), 10_000.0 / batch_ms * 1000.0);
    results
}
