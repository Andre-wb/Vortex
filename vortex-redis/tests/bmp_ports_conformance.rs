mod support;

use std::sync::Arc;

use vortex_bmp::config::rate::RateConfig;
use vortex_bmp::ports::clock::Clock;
use vortex_bmp::ports::rate_limiter::RateLimiter;
use vortex_bmp::ports::room_secrets::RoomSecrets;
use vortex_bmp::testing::{rate_limiter_conformance, secrets_conformance};
use vortex_redis::bmp::rate_limiter::RedisRateLimiter;
use vortex_redis::bmp::room_secrets::RedisRoomSecrets;

#[test]
fn the_redis_room_secrets_satisfy_the_same_port_contract_as_memory() {
    if support::backbone(&support::unique_prefix("secrets-probe")).is_none() {
        eprintln!("Redis недоступен — проверка секретов пропущена");
        return;
    }
    let make = || -> Arc<dyn RoomSecrets> {
        let prefix = support::unique_prefix("secrets");
        Arc::new(RedisRoomSecrets::new(support::backbone(&prefix).unwrap()))
    };
    secrets_conformance::check_all(&make);
}

#[test]
fn the_redis_rate_limiter_satisfies_the_same_port_contract_as_memory() {
    if support::backbone(&support::unique_prefix("rate-probe")).is_none() {
        eprintln!("Redis недоступен — проверка ограничителя пропущена");
        return;
    }
    let make = |clock: Arc<dyn Clock>, config: RateConfig| -> Arc<dyn RateLimiter> {
        let prefix = support::unique_prefix("rate");
        Arc::new(RedisRateLimiter::new(
            support::backbone(&prefix).unwrap(),
            clock,
            config,
        ))
    };
    rate_limiter_conformance::check_all(&make);
}
