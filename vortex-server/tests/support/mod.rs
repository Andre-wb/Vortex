#![allow(dead_code)]

use std::net::SocketAddr;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::Request;
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::Router;
use http::StatusCode;
use vortex_server::boot;
use vortex_server::router::build;
use vortex_server::settings::listen::ListenAddress;
use vortex_server::settings::server::ServerSettings;
use vortex_server::settings::upstream::UpstreamOrigin;
use vortex_server::state::SharedState;

pub const LIVENESS_BODY: &str = r#"{"status":"ok","version":"1.0.0","instance_id":"worker-7","crypto_backend":"rust","key_exchange":"X25519+HKDF-SHA256","post_quantum":"none","encryption":"AES-256-GCM","password_hash":"Argon2id","authentication":"JWT-HS256","federation":"enabled","database":"sqlite","redis":"disabled","scaling":"single-node","network_mode":"local","active_peers":2,"ws_connections":5,"own_ip":"10.0.0.9","uptime_seconds":42.5,"ephemeral":false,"metadata_padding":true}"#;

pub const READINESS_BODY: &str = r#"{"status":"ready","database":"ok","uploads_dir":"ok","keys_dir":"ok","background_tasks":"3/3 alive"}"#;

pub struct Node {
    pub edge: String,
    pub state: SharedState,
}

pub async fn stub_upstream() -> String {
    let router = Router::new()
        .route("/health", get(|| async { json(LIVENESS_BODY) }))
        .route("/health/ready", get(|| async { json(READINESS_BODY) }))
        .route("/metrics", get(|| async { "python_exposition 1" }))
        .route("/ws/echo", get(echo_socket))
        .fallback(any(echo));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("порт для заглушки");
    let address = listener.local_addr().expect("адрес заглушки");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{address}")
}

pub async fn start(settings: ServerSettings) -> Node {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("порт для края");
    let address = listener.local_addr().expect("адрес края");
    let state = boot::assemble(settings).await.expect("сервис собирается");
    let router = build::build(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Node {
        edge: format!("http://{address}"),
        state,
    }
}

pub fn settings_for(upstream: &str) -> ServerSettings {
    ServerSettings {
        listen: ListenAddress::new("127.0.0.1", 0),
        upstream: UpstreamOrigin::new(upstream),
        ..ServerSettings::default()
    }
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("клиент собирается")
}

fn json(body: &'static str) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        body,
    )
}

async fn echo_socket(upgrade: WebSocketUpgrade) -> impl IntoResponse {
    upgrade.on_upgrade(mirror)
}

async fn mirror(mut socket: WebSocket) {
    while let Some(Ok(message)) = socket.recv().await {
        if let Message::Text(text) = message {
            if socket
                .send(Message::Text(format!("эхо: {text}").into()))
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

async fn echo(request: Request) -> impl IntoResponse {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();
    let carried = request
        .headers()
        .get("x-carried")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "application/json")],
        serde_json::json!({
            "method": method,
            "path": path,
            "query": query,
            "carried": carried,
        })
        .to_string(),
    )
}
