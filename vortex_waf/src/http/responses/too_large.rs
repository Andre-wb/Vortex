//! Ответ 413 на слишком большое тело запроса.

use crate::http::responses::http_response::HttpResponse;
use serde_json::json;

pub fn build(max_bytes: usize) -> HttpResponse {
    let body = json!({
        "error": "Request entity too large",
        "max_bytes": max_bytes,
    });
    HttpResponse::json(413, body.to_string().into_bytes()).with_header("connection", "close")
}

#[cfg(test)]
mod tests {
    use super::build;

    #[test]
    fn reports_the_limit_and_closes_the_connection() {
        let response = build(1024);
        assert_eq!(response.status, 413);
        assert_eq!(response.header("connection"), Some("close"));
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["max_bytes"], 1024);
    }
}
