use std::time::Instant;

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

pub const STATIC_PREFIX: &str = "/static/";
pub const BMP_PREFIX: &str = "/api/bmp/";
pub const BMP_MASK: &str = "/api/bmp/***";
pub const WS_PREFIX: &str = "/ws/";
pub const WS_MASK: &str = "/ws/***";
pub const WS_NOTIFICATIONS: &str = "/ws/notifications";

pub fn sanitized(path: &str) -> String {
    if path.starts_with(BMP_PREFIX) {
        return BMP_MASK.to_string();
    }
    if path.starts_with(WS_PREFIX) && !path.starts_with(WS_NOTIFICATIONS) {
        return WS_MASK.to_string();
    }
    path.to_string()
}

pub async fn record(request: Request<Body>, next: Next) -> Response {
    let websocket = request
        .headers()
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if websocket || request.uri().path().starts_with(STATIC_PREFIX) {
        return next.run(request).await;
    }

    let method = request.method().clone();
    let path = sanitized(request.uri().path());
    let started = Instant::now();
    let response = next.run(request).await;
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    tracing::info!(
        "{method:6} {path:<40} {} {elapsed:6.1}ms",
        response.status().as_u16()
    );
    response
}

#[cfg(test)]
mod tests {
    use super::{sanitized, BMP_MASK, WS_MASK, WS_NOTIFICATIONS};

    #[test]
    fn a_mailbox_path_never_reaches_the_log_verbatim() {
        assert_eq!(sanitized("/api/bmp/ab12cd34"), BMP_MASK);
    }

    #[test]
    fn a_room_socket_is_masked_but_the_notification_socket_is_not() {
        assert_eq!(sanitized("/ws/chat/42"), WS_MASK);
        assert_eq!(sanitized(WS_NOTIFICATIONS), WS_NOTIFICATIONS);
    }

    #[test]
    fn an_ordinary_path_is_logged_as_it_came() {
        assert_eq!(sanitized("/health"), "/health");
    }
}
