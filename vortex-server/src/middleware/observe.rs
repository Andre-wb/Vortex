use std::time::Instant;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::metrics::normalize;
use crate::state::SharedState;

pub const SKIPPED: [&str; 3] = ["/metrics", "/health", "/favicon.ico"];
pub const STATIC_PREFIX: &str = "/static/";

pub fn counted(path: &str) -> bool {
    !SKIPPED.contains(&path) && !path.starts_with(STATIC_PREFIX)
}

pub async fn note(
    State(state): State<SharedState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    if !counted(&path) {
        return next.run(request).await;
    }

    let method = request.method().to_string();
    let endpoint = normalize::endpoint(&path);
    let started = Instant::now();
    let response = next.run(request).await;
    state.metrics.note(
        &method,
        &endpoint,
        response.status().as_u16(),
        started.elapsed().as_secs_f64(),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::counted;

    #[test]
    fn the_same_four_paths_are_skipped_as_in_the_python_middleware() {
        assert!(!counted("/metrics"));
        assert!(!counted("/health"));
        assert!(!counted("/favicon.ico"));
        assert!(!counted("/static/app.js"));
    }

    #[test]
    fn the_readiness_probe_is_counted_because_python_counts_it_too() {
        assert!(counted("/health/ready"));
        assert!(counted("/api/rooms"));
    }
}
