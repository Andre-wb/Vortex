//! Ответ 429 при неверном ответе на капчу.

use crate::http::responses::http_response::HttpResponse;
use serde_json::json;

/// Через сколько секунд клиенту стоит повторить попытку.
pub const RETRY_AFTER_SECS: u64 = 30;

pub fn build() -> HttpResponse {
    let body = json!({
        "error": "CAPTCHA verification required",
        "message": "Please solve the CAPTCHA to continue",
        "retry_after": RETRY_AFTER_SECS,
    });
    HttpResponse::json(429, body.to_string().into_bytes())
        .with_header("x-waf-captcha-required", "true")
}

#[cfg(test)]
mod tests {
    use super::build;

    #[test]
    fn marks_the_response_for_the_client() {
        let response = build();
        assert_eq!(response.status, 429);
        assert_eq!(response.header("x-waf-captcha-required"), Some("true"));
    }
}
