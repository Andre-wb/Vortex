use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::header::{HeaderName, HeaderValue};

use crate::middleware::csp_nonce;

pub const STATIC_PREFIX: &str = "/static/";

pub const FIXED: [(&str, &str); 8] = [
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("x-permitted-cross-domain-policies", "none"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    (
        "strict-transport-security",
        "max-age=31536000; includeSubDomains; preload",
    ),
];

pub const PERMISSIONS_POLICY: &str =
    "geolocation=(), payment=(), usb=(), microphone=(self), camera=(self)";

pub fn content_security_policy(nonce: &str) -> String {
    format!(
        "default-src 'self'; \
script-src 'self' 'nonce-{nonce}'; \
script-src-attr 'unsafe-inline'; \
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
font-src 'self' https://fonts.gstatic.com; \
img-src 'self' data: blob: https:; \
connect-src 'self' wss: ws: https:; \
media-src 'self' blob:; \
worker-src 'self' blob:; \
frame-src 'self'; \
frame-ancestors 'none'; \
object-src 'none'; \
base-uri 'self'; \
form-action 'self';"
    )
}

pub async fn apply(request: Request<Body>, next: Next) -> Response {
    let websocket = request
        .headers()
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if websocket {
        return next.run(request).await;
    }

    let is_static = request.uri().path().starts_with(STATIC_PREFIX);
    let nonce = csp_nonce::new_nonce();
    let mut response = next.run(request).await;
    if is_static {
        return response;
    }

    let headers = response.headers_mut();
    for (name, value) in FIXED {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if let Ok(policy) = HeaderValue::from_str(&content_security_policy(&nonce)) {
        headers.insert(http::header::CONTENT_SECURITY_POLICY, policy);
    }
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::{content_security_policy, FIXED, PERMISSIONS_POLICY};

    #[test]
    fn the_policy_carries_this_request_nonce_and_no_blanket_inline_script() {
        let policy = content_security_policy("тест-нонс");
        assert!(policy.contains("script-src 'self' 'nonce-тест-нонс';"));
        assert!(!policy.contains("script-src 'self' 'unsafe-inline'"));
        assert!(policy.contains("script-src-attr 'unsafe-inline';"));
    }

    #[test]
    fn the_fixed_headers_match_the_python_middleware() {
        let names: Vec<&str> = FIXED.iter().map(|(name, _)| *name).collect();
        assert!(names.contains(&"x-frame-options"));
        assert!(names.contains(&"strict-transport-security"));
        assert_eq!(FIXED.len(), 8);
        assert!(PERMISSIONS_POLICY.contains("camera=(self)"));
    }

    #[test]
    fn framing_is_denied_and_never_downgraded() {
        let deny = FIXED
            .iter()
            .find(|(name, _)| *name == "x-frame-options")
            .map(|(_, value)| *value);
        assert_eq!(deny, Some("DENY"));
    }
}
