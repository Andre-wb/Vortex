use axum::body::Body;
use axum::extract::State;
use axum::routing::get;
use axum::Router;
use http::{Request, Response};

use crate::health::liveness::handler as liveness;
use crate::health::readiness::handler as readiness;
use crate::metrics::handler as metrics;
use crate::middleware::{correlation, logging, observe, security_headers, stealth};
use crate::state::SharedState;

pub fn build(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(liveness::handle).head(liveness::handle))
        .route("/health/ready", get(readiness::handle))
        .route("/metrics", get(metrics::handle))
        .fallback(proxy)
        .layer(axum::middleware::from_fn(correlation::stamp))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            observe::note,
        ))
        .layer(axum::middleware::from_fn(logging::record))
        .layer(axum::middleware::from_fn(security_headers::apply))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            stealth::mask,
        ))
        .with_state(state)
}

async fn proxy(State(state): State<SharedState>, request: Request<Body>) -> Response<Body> {
    state.gateway.forward(request).await
}
