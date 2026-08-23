use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::{Result, ServerError};
use crate::health::facts::{LivenessFacts, ReadinessFacts};
use crate::ports::facts::NodeFactsSource;
use crate::settings::upstream::UpstreamOrigin;

pub const LIVENESS_PATH: &str = "/health";
pub const READINESS_PATH: &str = "/health/ready";
pub const DEFAULT_TIMEOUT_SECS: u64 = 3;

pub struct UpstreamNodeFacts {
    client: reqwest::Client,
    origin: UpstreamOrigin,
    timeout: Duration,
}

impl UpstreamNodeFacts {
    pub fn new(client: reqwest::Client, origin: UpstreamOrigin) -> Self {
        UpstreamNodeFacts {
            client,
            origin,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn ask(&self, path: &str) -> Result<(u16, Value)> {
        let answered = self
            .client
            .get(self.origin.join(path))
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|error| ServerError::Upstream(error.to_string()))?;
        let status = answered.status().as_u16();
        let raw = answered
            .bytes()
            .await
            .map_err(|error| ServerError::Upstream(error.to_string()))?;
        let reported: Value = serde_json::from_slice(&raw)
            .map_err(|error| ServerError::Upstream(error.to_string()))?;
        Ok((status, reported))
    }
}

#[async_trait]
impl NodeFactsSource for UpstreamNodeFacts {
    async fn liveness(&self) -> Result<LivenessFacts> {
        let (_, reported) = self.ask(LIVENESS_PATH).await?;
        Ok(LivenessFacts::read(&reported))
    }

    async fn readiness(&self) -> Result<ReadinessFacts> {
        let (status, reported) = self.ask(READINESS_PATH).await?;
        Ok(ReadinessFacts::read(status, &reported))
    }
}
