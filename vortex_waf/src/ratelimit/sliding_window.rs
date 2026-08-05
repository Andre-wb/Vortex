//! Ограничитель частоты по скользящему окну.

use crate::domain::client_ip::ClientIp;
use crate::domain::timestamp::Timestamp;
use crate::ports::clock::Clock;
use crate::ports::ip_allow_list::IpAllowList;
use crate::ports::ip_blocker::IpBlocker;
use crate::ports::prunable::Prunable;
use crate::ports::rate_limiter::{RateLimitOutcome, RateLimiter};
use crate::ratelimit::config::RateLimitConfig;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Причина, с которой адрес блокируется при грубом превышении.
pub const ESCALATION_REASON: &str = "Rate limit exceeded (double limit)";

pub struct SlidingWindowRateLimiter {
    config: RateLimitConfig,
    clock: Arc<dyn Clock>,
    allow_list: Arc<dyn IpAllowList>,
    blocker: Arc<dyn IpBlocker>,
    history: RwLock<HashMap<ClientIp, Vec<Timestamp>>>,
}

impl SlidingWindowRateLimiter {
    pub fn new(
        config: RateLimitConfig,
        clock: Arc<dyn Clock>,
        allow_list: Arc<dyn IpAllowList>,
        blocker: Arc<dyn IpBlocker>,
    ) -> Self {
        SlidingWindowRateLimiter {
            config,
            clock,
            allow_list,
            blocker,
            history: RwLock::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> RateLimitConfig {
        self.config
    }

    /// Сколько обращений адреса попадает в текущее окно.
    pub fn hits_in_window(&self, ip: &ClientIp) -> usize {
        let window_start = self.clock.now().minus_secs(self.config.window_secs);
        self.history
            .read()
            .expect("история запросов отравлена")
            .get(ip)
            .map(|hits| hits.iter().filter(|ts| **ts > window_start).count())
            .unwrap_or(0)
    }

    /// Учёт обращения. `None` — в пределах лимита; `Some((попаданий в окно,
    /// секунд до освобождения))` — лимит исчерпан.
    fn register(&self, ip: &ClientIp, now: Timestamp) -> Option<(usize, f64)> {
        let window_start = now.minus_secs(self.config.window_secs);
        let mut history = self.history.write().expect("история запросов отравлена");
        let hits = history.entry(ip.clone()).or_default();
        hits.retain(|ts| *ts > window_start);

        if hits.len() >= self.config.requests {
            let oldest = hits.iter().copied().min().unwrap_or(now);
            let wait = self.config.window_secs as f64 - now.secs_since(oldest);
            return Some((hits.len(), wait));
        }

        // После этой вставки длина не превышает `requests`: как только лимит
        // достигнут, обращения перестают записываться. Размер истории одного
        // адреса ограничен самим лимитом, отдельное усечение не нужно.
        hits.push(now);
        None
    }
}

impl RateLimiter for SlidingWindowRateLimiter {
    fn check(&self, ip: &ClientIp) -> RateLimitOutcome {
        if self.allow_list.contains(ip) {
            return RateLimitOutcome::Allowed;
        }

        // Замок истории отпущен до обращения к блокировщику.
        let Some((hits, wait)) = self.register(ip, self.clock.now()) else {
            return RateLimitOutcome::Allowed;
        };

        if hits >= self.config.escalation_threshold() {
            self.blocker
                .block(ip, ESCALATION_REASON, self.config.escalation_block_secs);
        }
        RateLimitOutcome::Exceeded {
            message: format!("Rate limit exceeded. Try again in {wait:.0} seconds."),
        }
    }
}

impl Prunable for SlidingWindowRateLimiter {
    fn name(&self) -> &'static str {
        "rate-limiter"
    }

    fn prune(&self) -> usize {
        // Адреса без обращений за два окна вычищаем целиком.
        let cutoff = self.clock.now().minus_secs(self.config.window_secs * 2);
        let mut history = self.history.write().expect("история запросов отравлена");
        let before = history.len();
        history.retain(|_, hits| hits.iter().any(|ts| *ts >= cutoff));
        before - history.len()
    }
}

#[cfg(test)]
mod tests {
    use super::SlidingWindowRateLimiter;
    use crate::blocking::allow_list::InMemoryAllowList;
    use crate::blocking::deny_list::InMemoryDenyList;
    use crate::blocking::memory_store::InMemoryBlockStore;
    use crate::blocking::reputation::IpReputation;
    use crate::domain::client_ip::ClientIp;
    use crate::ports::ip_gate::IpGate;
    use crate::ports::prunable::Prunable;
    use crate::ports::rate_limiter::{RateLimitOutcome, RateLimiter};
    use crate::ratelimit::config::RateLimitConfig;
    use crate::stats::in_memory::InMemoryStats;
    use crate::time::manual_clock::ManualClock;
    use std::sync::Arc;

    struct Fixture {
        limiter: SlidingWindowRateLimiter,
        clock: Arc<ManualClock>,
        reputation: Arc<IpReputation>,
    }

    fn fixture(config: RateLimitConfig) -> Fixture {
        let clock = Arc::new(ManualClock::at_epoch());
        let allow = Arc::new(InMemoryAllowList::with_loopback());
        let reputation = Arc::new(IpReputation::new(
            allow.clone(),
            Arc::new(InMemoryDenyList::empty()),
            Arc::new(InMemoryBlockStore::new(clock.clone())),
            clock.clone(),
            Arc::new(InMemoryStats::new()),
        ));
        Fixture {
            limiter: SlidingWindowRateLimiter::new(
                config,
                clock.clone(),
                allow,
                reputation.clone(),
            ),
            clock,
            reputation,
        }
    }

    #[test]
    fn allows_up_to_the_limit_then_refuses() {
        let f = fixture(RateLimitConfig::new(3, 60));
        let ip = ClientIp::from("1.1.1.1");
        for _ in 0..3 {
            assert!(f.limiter.check(&ip).is_allowed());
        }
        match f.limiter.check(&ip) {
            RateLimitOutcome::Exceeded { message } => {
                assert_eq!(message, "Rate limit exceeded. Try again in 60 seconds.");
            }
            RateLimitOutcome::Allowed => panic!("ожидался отказ"),
        }
    }

    #[test]
    fn wait_time_counts_down_with_the_window() {
        let f = fixture(RateLimitConfig::new(1, 60));
        let ip = ClientIp::from("1.1.1.2");
        assert!(f.limiter.check(&ip).is_allowed());
        f.clock.advance_secs(20);
        match f.limiter.check(&ip) {
            RateLimitOutcome::Exceeded { message } => {
                assert_eq!(message, "Rate limit exceeded. Try again in 40 seconds.");
            }
            RateLimitOutcome::Allowed => panic!("ожидался отказ"),
        }
    }

    #[test]
    fn window_slides_forward() {
        let f = fixture(RateLimitConfig::new(2, 60));
        let ip = ClientIp::from("2.2.2.2");
        assert!(f.limiter.check(&ip).is_allowed());
        assert!(f.limiter.check(&ip).is_allowed());
        assert!(!f.limiter.check(&ip).is_allowed());

        f.clock.advance_secs(61);
        assert!(f.limiter.check(&ip).is_allowed());
    }

    #[test]
    fn reaching_the_escalation_threshold_blocks_the_address() {
        // Порог опущен до самого лимита, иначе ветка недостижима: история
        // копится только из разрешённых обращений и не превышает лимит.
        let f = fixture(RateLimitConfig::new(2, 60).with_escalation_threshold(2));
        let ip = ClientIp::from("3.3.3.3");
        for _ in 0..2 {
            assert!(f.limiter.check(&ip).is_allowed());
        }
        assert!(!f.limiter.check(&ip).is_allowed());
        assert!(f.reputation.is_blocked(&ip));
    }

    #[test]
    fn default_threshold_leaves_the_address_unblocked() {
        let f = fixture(RateLimitConfig::new(2, 60));
        let ip = ClientIp::from("3.3.3.4");
        for _ in 0..5 {
            f.limiter.check(&ip);
        }
        assert!(!f.reputation.is_blocked(&ip));
    }

    #[test]
    fn whitelisted_ip_is_never_limited() {
        let f = fixture(RateLimitConfig::new(1, 60));
        let ip = ClientIp::from("127.0.0.1");
        for _ in 0..10 {
            assert!(f.limiter.check(&ip).is_allowed());
        }
    }

    #[test]
    fn prune_evicts_idle_addresses() {
        let f = fixture(RateLimitConfig::new(5, 60));
        let ip = ClientIp::from("5.5.5.5");
        f.limiter.check(&ip);
        assert_eq!(f.limiter.hits_in_window(&ip), 1);

        f.clock.advance_secs(200);
        assert_eq!(f.limiter.prune(), 1);
        assert_eq!(f.limiter.hits_in_window(&ip), 0);
    }
}
