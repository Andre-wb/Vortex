use std::sync::Arc;

use vortex_ratelimit::attempt::limit::Limit;
use vortex_ratelimit::attempt::subject::Subject;
use vortex_ratelimit::attempt::window::Window;
use vortex_ratelimit::error::{CountError, Result};
use vortex_ratelimit::ports::attempt_limiter::AttemptLimiter;
use vortex_ratelimit::ports::window_reset::WindowReset;

use fred::prelude::*;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::sliding_window;

pub const AUTH_DOMAIN: &str = "auth";
pub const RATELIMIT_DOMAIN: &str = "ratelimit";

const SEQUENCE: &str = "attempt-sequence";

pub struct RedisAttemptLimiter {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisAttemptLimiter {
    pub fn new(backbone: Arc<RedisBackbone>, domain: &'static str) -> Self {
        let space = backbone.key_space(domain);
        RedisAttemptLimiter { backbone, space }
    }

    pub fn for_auth(backbone: Arc<RedisBackbone>) -> Self {
        RedisAttemptLimiter::new(backbone, AUTH_DOMAIN)
    }

    pub fn for_rate_limits(backbone: Arc<RedisBackbone>) -> Self {
        RedisAttemptLimiter::new(backbone, RATELIMIT_DOMAIN)
    }

    fn window_key(&self, subject: &Subject) -> String {
        self.space.member_key(subject.bucket(), subject.member())
    }
}

impl AttemptLimiter for RedisAttemptLimiter {
    fn allow(&self, subject: &Subject, limit: Limit, window: Window, now: f64) -> Result<bool> {
        let window_key = self.window_key(subject);
        let sequence_key = self.space.key(SEQUENCE);
        let width = window.width();
        let ceiling = limit.value() as i64;

        self.backbone
            .execute("счёт попыток", move |pool| {
                let keys = vec![window_key.clone(), sequence_key.clone()];
                let args = vec![
                    now.to_string().into(),
                    width.to_string().into(),
                    ceiling.into(),
                ];
                async move { sliding_window::SCRIPT.run::<i64>(&pool, keys, args).await }
            })
            .map(|verdict| verdict == sliding_window::ALLOWED)
            .map_err(|_| CountError::Unavailable)
    }
}

impl WindowReset for RedisAttemptLimiter {
    fn forget(&self, subject: &Subject) -> Result<()> {
        let window_key = self.window_key(subject);
        self.backbone
            .execute("сброс окна попыток", move |pool| {
                let window_key = window_key.clone();
                async move { pool.del::<i64, _>(window_key).await }
            })
            .map(|_| ())
            .map_err(|_| CountError::Unavailable)
    }
}
