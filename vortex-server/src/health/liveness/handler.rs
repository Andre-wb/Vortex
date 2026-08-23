use axum::body::Body;
use axum::extract::State;
use http::{Request, Response, StatusCode};

use crate::health::degraded::DegradedReport;
use crate::health::liveness::report::LivenessReport;
use crate::response;
use crate::router::names;
use crate::state::SharedState;
use vortex_routing::handler::decision::Handler;

pub async fn handle(State(state): State<SharedState>, request: Request<Body>) -> Response<Body> {
    let route = names::named(names::HEALTH);
    if state.flags.resolve(&route).await == Handler::Python {
        return state.gateway.forward(request).await;
    }

    match state.facts.liveness().await {
        Ok(facts) => response::json(
            StatusCode::OK,
            &LivenessReport::compose(&state.settings.node, facts),
        ),
        Err(error) => {
            tracing::warn!("Python не ответил на /health: {error}");
            state.metrics.note_upstream_failure();
            response::json(
                StatusCode::SERVICE_UNAVAILABLE,
                &DegradedReport::compose(&state.settings.node),
            )
        }
    }
}
