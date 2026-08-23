use axum::body::Body;
use http::{HeaderValue, Response, StatusCode};

pub const CONTENT_TYPE: &str = "application/json";

pub fn bad_gateway(reason: &str) -> Response<Body> {
    tracing::warn!("прокси в Python не удался: {reason}");
    let body = serde_json::json!({
        "error": "Bad gateway",
        "status": StatusCode::BAD_GATEWAY.as_u16(),
    });
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE),
    );
    response
}
