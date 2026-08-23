use axum::body::Body;
use http::{HeaderMap, Response};

use crate::proxy::upgrade::socket::UpstreamSocket;

pub enum UpgradeOutcome {
    Switched {
        headers: HeaderMap,
        socket: Box<dyn UpstreamSocket>,
    },
    Refused(Response<Body>),
}
