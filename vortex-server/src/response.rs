use axum::body::Body;
use http::{HeaderValue, Response, StatusCode};
use serde::Serialize;

pub const CONTENT_TYPE: &str = "application/json";

pub fn json<T: Serialize>(status: StatusCode, payload: &T) -> Response<Body> {
    let rendered = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    let mut response = Response::new(Body::from(rendered));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE),
    );
    response
}

pub fn text(status: StatusCode, content_type: &'static str, body: String) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    response
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use serde_json::json;

    use super::{json as as_json, CONTENT_TYPE};

    #[test]
    fn a_json_answer_always_declares_its_content_type() {
        let response = as_json(StatusCode::OK, &json!({"status": "ok"}));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE).unwrap(),
            CONTENT_TYPE
        );
    }
}
