use std::sync::Arc;

use vortex_bmp::config::rate::RateConfig;
use vortex_bmp::ports::clock::Clock;
use vortex_bmp::ports::rate_limiter::RateLimiter;
use vortex_bmp::ratelimit::sliding_window::SlidingWindowLimiter;

use crate::backbone::RedisBackbone;
use crate::bmp::scripts;
use crate::keys::KeySpace;

const DOMAIN: &str = "bmp";
const WINDOW_NAME: &str = "rate";

pub struct RedisRateLimiter {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<SlidingWindowLimiter>,
    clock: Arc<dyn Clock>,
    config: RateConfig,
    space: KeySpace,
}

impl RedisRateLimiter {
    pub fn new(backbone: Arc<RedisBackbone>, clock: Arc<dyn Clock>, config: RateConfig) -> Self {
        let space = backbone.key_space(DOMAIN);
        let fallback = Arc::new(SlidingWindowLimiter::new(clock.clone(), config));
        RedisRateLimiter {
            backbone,
            fallback,
            clock,
            config,
            space,
        }
    }

    pub fn fallback(&self) -> &Arc<SlidingWindowLimiter> {
        &self.fallback
    }
}

impl RateLimiter for RedisRateLimiter {
    fn allow(&self, key: &str, limit: u32) -> bool {
        let window_key = self.space.member_key(WINDOW_NAME, key);
        let sequence_key = self.space.key("rate-sequence");
        let window = self.config.window_secs;
        let now = self.clock.unix_seconds();

        let verdict = self.backbone.execute("проверка частоты", move |pool| {
            let keys = vec![window_key.clone(), sequence_key.clone()];
            let args = vec![
                now.to_string().into(),
                window.to_string().into(),
                (limit as i64).into(),
            ];
            async move { scripts::SLIDING_WINDOW.run::<i64>(&pool, keys, args).await }
        });

        match verdict {
            Ok(allowed) => allowed == 1,
            Err(_) => self.fallback.allow(key, limit),
        }
    }

    fn forget_stale(&self) {
        self.fallback.forget_stale();
    }

    fn tracked_keys(&self) -> usize {
        self.fallback.tracked_keys()
    }
}
