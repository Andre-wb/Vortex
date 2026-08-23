use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http::header::{HeaderName, HeaderValue};
use http::StatusCode;

use crate::response as answer;
use crate::state::SharedState;

pub const BLOCKED: [&str; 4] = ["/health", "/api/docs", "/api/redoc", "/openapi.json"];
pub const MANIFEST: [&str; 2] = ["/manifest.json", "/static/manifest.json"];
pub const STRIPPED: [&str; 2] = ["x-powered-by", "x-aspnet-version"];
pub const PLAIN_TEXT: &str = "text/plain; charset=utf-8";

pub fn decoy_manifest() -> serde_json::Value {
    serde_json::json!({
        "name": "Web App",
        "short_name": "App",
        "start_url": "/",
        "display": "standalone"
    })
}

pub async fn mask(
    State(state): State<SharedState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !state.settings.stealth.enabled() {
        return next.run(request).await;
    }

    let path = request.uri().path().to_string();
    if BLOCKED.contains(&path.as_str()) {
        return answer::text(StatusCode::NOT_FOUND, PLAIN_TEXT, "Not Found".to_string());
    }
    if MANIFEST.contains(&path.as_str()) {
        return answer::json(StatusCode::OK, &decoy_manifest());
    }

    let mut response = next.run(request).await;
    sanitize(&mut response);
    response
}

pub fn sanitize(response: &mut Response) {
    let headers = response.headers_mut();
    for name in STRIPPED {
        headers.remove(name);
    }
    headers.insert(
        HeaderName::from_static("server"),
        HeaderValue::from_static("nginx"),
    );
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    let branded: Vec<HeaderName> = headers
        .keys()
        .filter(|name| name.as_str().contains("vortex"))
        .cloned()
        .collect();
    for name in branded {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::response::Response;
    use http::header::{HeaderName, HeaderValue};

    use super::{decoy_manifest, sanitize, BLOCKED};

    #[test]
    fn the_health_route_is_among_the_blocked_paths() {
        assert!(BLOCKED.contains(&"/health"));
        assert!(BLOCKED.contains(&"/openapi.json"));
    }

    #[test]
    fn the_decoy_manifest_names_no_product() {
        let rendered = decoy_manifest().to_string();
        assert!(!rendered.to_lowercase().contains("vortex"));
        assert!(rendered.contains("Web App"));
    }

    #[test]
    fn sanitizing_strips_the_brand_and_never_downgrades_framing() {
        let mut response = Response::new(Body::empty());
        response.headers_mut().insert(
            HeaderName::from_static("x-vortex-node"),
            HeaderValue::from_static("node-1"),
        );
        response.headers_mut().insert(
            HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("uvicorn"),
        );
        response.headers_mut().insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("SAMEORIGIN"),
        );
        sanitize(&mut response);
        let headers = response.headers();
        assert!(!headers.contains_key("x-vortex-node"));
        assert!(!headers.contains_key("x-powered-by"));
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("server").unwrap(), "nginx");
    }
}
