use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use http::{Request, Response, StatusCode};
use reqwest::redirect::Policy;

use crate::error::{Result, ServerError};
use crate::ports::relay::Relay;
use crate::ports::upgrade_relay::UpgradeRelay;
use crate::proxy::hop;
use crate::proxy::target;
use crate::proxy::upgrade::outcome::UpgradeOutcome;
use crate::settings::upstream::UpstreamOrigin;

pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;

pub struct UpstreamClient {
    client: reqwest::Client,
    origin: UpstreamOrigin,
}

impl UpstreamClient {
    pub fn new(origin: UpstreamOrigin) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .build()
            .map_err(|error| ServerError::Upstream(error.to_string()))?;
        Ok(UpstreamClient { client, origin })
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    pub fn origin(&self) -> &UpstreamOrigin {
        &self.origin
    }
}

#[async_trait]
impl Relay for UpstreamClient {
    async fn relay(&self, request: Request<Body>) -> Result<Response<Body>> {
        let (parts, body) = request.into_parts();
        let url = self.origin.join(&target::path_and_query(&parts.uri));
        let answered = self
            .client
            .request(parts.method, url)
            .headers(hop::end_to_end(&parts.headers))
            .body(reqwest::Body::wrap_stream(body.into_data_stream()))
            .send()
            .await
            .map_err(|error| ServerError::Upstream(error.to_string()))?;
        Ok(into_response(answered))
    }
}

#[async_trait]
impl UpgradeRelay for UpstreamClient {
    async fn open(&self, request: Request<Body>) -> Result<UpgradeOutcome> {
        let (parts, _) = request.into_parts();
        let url = self.origin.join(&target::path_and_query(&parts.uri));
        let answered = self
            .client
            .request(parts.method, url)
            .version(http::Version::HTTP_11)
            .headers(hop::for_upgrade(&parts.headers))
            .send()
            .await
            .map_err(|error| ServerError::Upstream(error.to_string()))?;

        if answered.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Ok(UpgradeOutcome::Refused(into_response(answered)));
        }

        let headers = answered.headers().clone();
        let socket = answered
            .upgrade()
            .await
            .map_err(|error| ServerError::Upstream(error.to_string()))?;
        Ok(UpgradeOutcome::Switched {
            headers,
            socket: Box::new(socket),
        })
    }
}

fn into_response(answered: reqwest::Response) -> Response<Body> {
    let status = answered.status();
    let headers = hop::end_to_end(answered.headers());
    let mut response = Response::new(Body::from_stream(answered.bytes_stream()));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}
