use std::sync::Arc;

use vortex_ratelimit::antispam::memory::MemoryRepeatLedger;
use vortex_ratelimit::antispam::unavailable::UnavailableRepeatLedger;
use vortex_ratelimit::attempt::memory::MemoryAttemptLimiter;
use vortex_ratelimit::attempt::unavailable::UnavailableAttemptLimiter;
use vortex_ratelimit::flood::memory::MemoryStrikeLedger;
use vortex_ratelimit::ports::attempt_limiter::AttemptLimiter;
use vortex_ratelimit::ports::repeat_ledger::RepeatLedger;
use vortex_ratelimit::ports::strike_ledger::StrikeLedger;
use vortex_ratelimit::ports::window_reset::WindowReset;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::ratelimit::attempt_limiter::RedisAttemptLimiter;
use vortex_redis::ratelimit::flood_window::RedisFloodWindow;
use vortex_redis::ratelimit::repeat_ledger::RedisRepeatLedger;
use vortex_redis::ratelimit::strike_ledger::RedisStrikeLedger;

pub struct Stores {
    pub attempts: Arc<dyn AttemptLimiter>,
    pub attempts_reset: Arc<dyn WindowReset>,
    pub flood_window: Arc<dyn AttemptLimiter>,
    pub flood_reset: Arc<dyn WindowReset>,
    pub repeats: Arc<dyn RepeatLedger>,
    pub repeats_reset: Arc<dyn WindowReset>,
    pub strikes: Arc<dyn StrikeLedger>,
}

impl Stores {
    pub fn in_memory() -> Self {
        let attempts = Arc::new(MemoryAttemptLimiter::new());
        let repeats = Arc::new(MemoryRepeatLedger::new());
        Stores::counting_flood_in_memory(attempts.clone(), attempts, repeats.clone(), repeats)
    }

    pub fn sealed() -> Self {
        let attempts = Arc::new(UnavailableAttemptLimiter::new());
        Stores::counting_flood_in_memory(
            attempts.clone(),
            attempts,
            Arc::new(UnavailableRepeatLedger::new()),
            Arc::new(UnavailableAttemptLimiter::new()),
        )
    }

    pub fn in_redis(backbone: Arc<RedisBackbone>) -> Self {
        let attempts = Arc::new(RedisAttemptLimiter::for_rate_limits(backbone.clone()));
        let flood = Arc::new(RedisFloodWindow::new(backbone.clone()));
        let repeats = Arc::new(RedisRepeatLedger::new(backbone.clone()));
        Stores {
            attempts: attempts.clone(),
            attempts_reset: attempts,
            flood_window: flood.clone(),
            flood_reset: flood,
            repeats: repeats.clone(),
            repeats_reset: repeats,
            strikes: Arc::new(RedisStrikeLedger::new(backbone)),
        }
    }

    fn counting_flood_in_memory(
        attempts: Arc<dyn AttemptLimiter>,
        attempts_reset: Arc<dyn WindowReset>,
        repeats: Arc<dyn RepeatLedger>,
        repeats_reset: Arc<dyn WindowReset>,
    ) -> Self {
        let flood = Arc::new(MemoryAttemptLimiter::new());
        Stores {
            attempts,
            attempts_reset,
            flood_window: flood.clone(),
            flood_reset: flood,
            repeats,
            repeats_reset,
            strikes: Arc::new(MemoryStrikeLedger::new()),
        }
    }
}
