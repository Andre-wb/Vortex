pub const REQUESTS: &str = "vortex_edge_requests_total";
pub const REQUESTS_HELP: &str = "Запросы, обслуженные краевым Rust-сервисом";
pub const DURATION: &str = "vortex_edge_request_duration_seconds";
pub const DURATION_HELP: &str = "Время ответа краевого Rust-сервиса";
pub const UPSTREAM_FAILURES: &str = "vortex_edge_upstream_failures_total";
pub const UPSTREAM_FAILURES_HELP: &str = "Запросы, на которые Python не ответил";

pub const BUCKETS: [f64; 8] = [0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

#[cfg(test)]
mod tests {
    use super::{DURATION, REQUESTS, UPSTREAM_FAILURES};

    #[test]
    fn no_family_collides_with_the_python_exposition() {
        for name in [REQUESTS, DURATION, UPSTREAM_FAILURES] {
            assert!(name.starts_with("vortex_edge_"), "{name}");
            assert!(!name.starts_with("vortex_http_"), "{name}");
            assert!(!name.starts_with("vortex_ws_"), "{name}");
            assert!(!name.starts_with("vortex_peers_"), "{name}");
            assert!(!name.starts_with("vortex_db_"), "{name}");
        }
    }
}
