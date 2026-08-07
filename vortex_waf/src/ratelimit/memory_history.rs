//! История обращений в памяти процесса.

use crate::domain::client_ip::ClientIp;
use crate::domain::timestamp::Timestamp;
use crate::ports::request_history::RequestHistory;
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Default)]
pub struct InMemoryRequestHistory {
    hits: RwLock<HashMap<ClientIp, Vec<Timestamp>>>,
}

impl InMemoryRequestHistory {
    pub fn new() -> Self {
        InMemoryRequestHistory::default()
    }

    fn lock(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<ClientIp, Vec<Timestamp>>> {
        self.hits.write().expect("история запросов отравлена")
    }
}

impl RequestHistory for InMemoryRequestHistory {
    fn register(
        &self,
        ip: &ClientIp,
        now: Timestamp,
        requests: usize,
        window_secs: u64,
    ) -> Option<(usize, f64)> {
        let window_start = now.minus_secs(window_secs);
        let mut hits = self.lock();
        let entry = hits.entry(ip.clone()).or_default();
        entry.retain(|stamp| *stamp > window_start);

        if entry.len() >= requests {
            let oldest = entry.iter().copied().min().unwrap_or(now);
            let wait = window_secs as f64 - now.secs_since(oldest);
            return Some((entry.len(), wait));
        }

        // После вставки длина не превышает `requests`: как только лимит достигнут,
        // обращения перестают записываться, поэтому история одного адреса
        // ограничена самим лимитом.
        entry.push(now);
        None
    }

    fn hits_in_window(&self, ip: &ClientIp, now: Timestamp, window_secs: u64) -> usize {
        let window_start = now.minus_secs(window_secs);
        self.hits
            .read()
            .expect("история запросов отравлена")
            .get(ip)
            .map(|hits| hits.iter().filter(|stamp| **stamp > window_start).count())
            .unwrap_or(0)
    }

    fn forget_stale(&self, now: Timestamp, window_secs: u64) -> usize {
        let cutoff = now.minus_secs(window_secs);
        let mut hits = self.lock();
        let before = hits.len();
        hits.retain(|_, stamps| stamps.iter().any(|stamp| *stamp >= cutoff));
        before - hits.len()
    }

    fn tracked_clients(&self) -> usize {
        self.hits.read().expect("история запросов отравлена").len()
    }
}
