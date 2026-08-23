use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use http::{Request, Response, StatusCode};
use std::net::SocketAddr;

use crate::metrics::access;
use crate::response;
use crate::router::names;
use crate::state::SharedState;
use vortex_routing::handler::decision::Handler;

pub const EXPOSITION_TYPE: &str = "text/plain; version=0.0.4";

pub async fn handle(State(state): State<SharedState>, request: Request<Body>) -> Response<Body> {
    let route = names::named(names::METRICS);
    if state.flags.resolve(&route).await == Handler::Python {
        return state.gateway.forward(request).await;
    }

    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip());
    if !access::allowed(peer, request.headers(), &state.settings.metrics_token) {
        return response::json(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"detail": "Not Found"}),
        );
    }

    response::text(StatusCode::OK, EXPOSITION_TYPE, state.metrics.render())
}
