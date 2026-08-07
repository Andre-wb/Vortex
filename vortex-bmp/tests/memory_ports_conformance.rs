use std::sync::Arc;

use vortex_bmp::config::rate::RateConfig;
use vortex_bmp::ports::clock::Clock;
use vortex_bmp::ports::rate_limiter::RateLimiter;
use vortex_bmp::ports::room_secrets::RoomSecrets;
use vortex_bmp::ratelimit::sliding_window::SlidingWindowLimiter;
use vortex_bmp::secrets::memory_secrets::MemoryRoomSecrets;
use vortex_bmp::testing::{rate_limiter_conformance, secrets_conformance};

#[test]
fn the_in_memory_room_secrets_satisfy_the_port_contract() {
    let make = || -> Arc<dyn RoomSecrets> { Arc::new(MemoryRoomSecrets::new()) };
    secrets_conformance::check_all(&make);
}

#[test]
fn the_in_memory_rate_limiter_satisfies_the_port_contract() {
    let make = |clock: Arc<dyn Clock>, config: RateConfig| -> Arc<dyn RateLimiter> {
        Arc::new(SlidingWindowLimiter::new(clock, config))
    };
    rate_limiter_conformance::check_all(&make);
}
