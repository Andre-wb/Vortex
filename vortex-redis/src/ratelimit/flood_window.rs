use std::sync::Arc;

use fred::prelude::*;
use vortex_ratelimit::attempt::limit::Limit;
use vortex_ratelimit::attempt::memory::MemoryAttemptLimiter;
use vortex_ratelimit::attempt::subject::Subject;
use vortex_ratelimit::attempt::window::Window;
use vortex_ratelimit::error::Result;
use vortex_ratelimit::ports::attempt_limiter::AttemptLimiter;
use vortex_ratelimit::ports::window_reset::WindowReset;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::ratelimit::attempt_limiter::RATELIMIT_DOMAIN;
use crate::sliding_window;

const SEQUENCE: &str = "flood-sequence";

pub struct RedisFloodWindow {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<MemoryAttemptLimiter>,
    space: KeySpace,
}

impl RedisFloodWindow {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(RATELIMIT_DOMAIN);
        RedisFloodWindow {
            backbone,
            fallback: Arc::new(MemoryAttemptLimiter::new()),
            space,
        }
    }

    pub fn fallback(&self) -> &Arc<MemoryAttemptLimiter> {
        &self.fallback
    }

    fn window_key(&self, subject: &Subject) -> String {
        self.space.member_key(subject.bucket(), subject.member())
    }
}

impl AttemptLimiter for RedisFloodWindow {
    fn allow(&self, subject: &Subject, limit: Limit, window: Window, now: f64) -> Result<bool> {
        let window_key = self.window_key(subject);
        let sequence_key = self.space.key(SEQUENCE);
        let width = window.width();
        let ceiling = limit.value() as i64;

        let verdict =
            self.backbone
                .execute("счёт сообщений комнаты", move |pool| {
                    let keys = vec![window_key.clone(), sequence_key.clone()];
                    let args = vec![
                        now.to_string().into(),
                        width.to_string().into(),
                        ceiling.into(),
                    ];
                    async move { sliding_window::SCRIPT.run::<i64>(&pool, keys, args).await }
                });

        match verdict {
            Ok(allowed) => Ok(allowed == sliding_window::ALLOWED),
            Err(_) => self.fallback.allow(subject, limit, window, now),
        }
    }
}

impl WindowReset for RedisFloodWindow {
    fn forget(&self, subject: &Subject) -> Result<()> {
        let window_key = self.window_key(subject);
        let cleared = self.backbone.execute("сброс окна флуда", move |pool| {
            let window_key = window_key.clone();
            async move { pool.del::<i64, _>(window_key).await }
        });

        match cleared {
            Ok(_) => Ok(()),
            Err(_) => self.fallback.forget(subject),
        }
    }
}
