use prometheus::{
    HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
};

use crate::metrics::families;

pub struct EdgeMetrics {
    registry: Registry,
    requests: IntCounterVec,
    duration: HistogramVec,
    upstream_failures: IntCounter,
}

impl EdgeMetrics {
    pub fn new() -> prometheus::Result<Self> {
        let registry = Registry::new();
        let requests = IntCounterVec::new(
            Opts::new(families::REQUESTS, families::REQUESTS_HELP),
            &["method", "endpoint", "status"],
        )?;
        let duration = HistogramVec::new(
            HistogramOpts::new(families::DURATION, families::DURATION_HELP)
                .buckets(families::BUCKETS.to_vec()),
            &["method", "endpoint"],
        )?;
        let upstream_failures = IntCounter::new(
            families::UPSTREAM_FAILURES,
            families::UPSTREAM_FAILURES_HELP,
        )?;
        registry.register(Box::new(requests.clone()))?;
        registry.register(Box::new(duration.clone()))?;
        registry.register(Box::new(upstream_failures.clone()))?;
        Ok(EdgeMetrics {
            registry,
            requests,
            duration,
            upstream_failures,
        })
    }

    pub fn note(&self, method: &str, endpoint: &str, status: u16, seconds: f64) {
        self.requests
            .with_label_values(&[method, endpoint, &status.to_string()])
            .inc();
        self.duration
            .with_label_values(&[method, endpoint])
            .observe(seconds);
    }

    pub fn note_upstream_failure(&self) {
        self.upstream_failures.inc();
    }

    pub fn render(&self) -> String {
        TextEncoder::new()
            .encode_to_string(&self.registry.gather())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::EdgeMetrics;
    use crate::metrics::families;

    #[test]
    fn a_recorded_request_shows_up_in_the_exposition() {
        let metrics = EdgeMetrics::new().expect("реестр создаётся");
        metrics.note("GET", "/health", 200, 0.004);
        let rendered = metrics.render();
        assert!(rendered.contains(families::REQUESTS));
        assert!(rendered.contains(r#"endpoint="/health""#));
        assert!(rendered.contains(families::DURATION));
    }

    #[test]
    fn the_exposition_never_carries_a_python_family_name() {
        let metrics = EdgeMetrics::new().expect("реестр создаётся");
        metrics.note("GET", "/health", 200, 0.004);
        metrics.note_upstream_failure();
        let rendered = metrics.render();
        assert!(!rendered.contains("vortex_http_requests_total"));
        assert!(!rendered.contains("vortex_ws_connections_active"));
        assert!(rendered.contains(families::UPSTREAM_FAILURES));
    }

    #[test]
    fn two_registries_never_share_a_counter() {
        let first = EdgeMetrics::new().expect("реестр создаётся");
        let second = EdgeMetrics::new().expect("реестр создаётся");
        first.note("GET", "/health", 200, 0.001);
        assert!(second.render().is_empty() || !second.render().contains("1"));
    }
}
