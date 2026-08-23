use std::sync::Arc;

use axum::body::Body;
use http::{Request, Response};

use crate::ports::relay::Relay;
use crate::ports::upgrade_relay::UpgradeRelay;
use crate::proxy::refusal;
use crate::proxy::upgrade::bridge::bridge;
use crate::proxy::upgrade::detect::requests_websocket;

pub struct Gateway<T> {
    upstream: Arc<T>,
}

impl<T> Gateway<T>
where
    T: Relay + UpgradeRelay,
{
    pub fn new(upstream: Arc<T>) -> Self {
        Gateway { upstream }
    }

    pub async fn forward(&self, request: Request<Body>) -> Response<Body> {
        if requests_websocket(request.headers()) {
            return bridge(self.upstream.as_ref(), request).await;
        }
        match self.upstream.relay(request).await {
            Ok(response) => response,
            Err(error) => refusal::bad_gateway(&error.to_string()),
        }
    }
}
