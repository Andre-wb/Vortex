use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::HeaderValue;
use rand::RngCore;

pub const HEADER: &str = "x-request-id";
pub const LENGTH: usize = 12;

pub fn new_identifier() -> String {
    let mut bytes = [0u8; LENGTH / 2];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub async fn stamp(request: Request<Body>, next: Next) -> Response {
    let carried = request
        .headers()
        .get(HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let identifier = carried.unwrap_or_else(new_identifier);

    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&identifier) {
        response.headers_mut().insert(HEADER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::{new_identifier, LENGTH};

    #[test]
    fn an_identifier_is_twelve_hex_characters_like_the_python_one() {
        let identifier = new_identifier();
        assert_eq!(identifier.len(), LENGTH);
        assert!(identifier.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn two_identifiers_differ() {
        assert_ne!(new_identifier(), new_identifier());
    }
}
