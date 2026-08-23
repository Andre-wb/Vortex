use axum::body::Body;
use axum::extract::State;
use http::{Request, Response, StatusCode};

use crate::health::degraded::DegradedReport;
use crate::health::readiness::checks::LocalChecks;
use crate::health::readiness::report::ReadinessReport;
use crate::response;
use crate::router::names;
use crate::state::SharedState;
use vortex_routing::handler::decision::Handler;

pub async fn handle(State(state): State<SharedState>, request: Request<Body>) -> Response<Body> {
    let route = names::named(names::HEALTH_READY);
    if state.flags.resolve(&route).await == Handler::Python {
        return state.gateway.forward(request).await;
    }

    let checks = LocalChecks::run(&state.settings.paths);
    match state.facts.readiness().await {
        Ok(facts) => {
            let report = ReadinessReport::compose(checks, facts);
            let status =
                StatusCode::from_u16(report.code()).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
            response::json(status, &report)
        }
        Err(error) => {
            tracing::warn!("Python не ответил на /health/ready: {error}");
            state.metrics.note_upstream_failure();
            response::json(
                StatusCode::SERVICE_UNAVAILABLE,
                &DegradedReport::compose(&state.settings.node),
            )
        }
    }
}
