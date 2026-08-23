use std::sync::Arc;

use vortex_ratelimit::antispam::memory::MemoryRepeatLedger;
use vortex_ratelimit::attempt::memory::MemoryAttemptLimiter;
use vortex_ratelimit::flood::memory::MemoryStrikeLedger;
use vortex_ratelimit::ports::attempt_limiter::AttemptLimiter;
use vortex_ratelimit::ports::repeat_ledger::RepeatLedger;
use vortex_ratelimit::ports::strike_ledger::StrikeLedger;
use vortex_ratelimit::ports::window_reset::WindowReset;
use vortex_ratelimit::testing::{
    attempt_limiter_conformance, repeat_ledger_conformance, strike_ledger_conformance,
    window_reset_conformance,
};

#[test]
fn the_attempt_limiter_in_memory_satisfies_the_port_contract() {
    let make = || -> Arc<dyn AttemptLimiter> { Arc::new(MemoryAttemptLimiter::new()) };
    attempt_limiter_conformance::check_all(&make);
}

#[test]
fn the_strike_ledger_in_memory_satisfies_the_port_contract() {
    let make = || -> Arc<dyn StrikeLedger> { Arc::new(MemoryStrikeLedger::new()) };
    strike_ledger_conformance::check_all(&make);
}

#[test]
fn forgetting_a_window_in_memory_satisfies_the_port_contract() {
    let make = || -> (Arc<dyn AttemptLimiter>, Arc<dyn WindowReset>) {
        let limiter = Arc::new(MemoryAttemptLimiter::new());
        (limiter.clone(), limiter)
    };
    window_reset_conformance::check_all(&make);
}

#[test]
fn the_repeat_ledger_in_memory_satisfies_the_port_contract() {
    let make = || -> (Arc<dyn RepeatLedger>, Arc<dyn WindowReset>) {
        let ledger = Arc::new(MemoryRepeatLedger::new());
        (ledger.clone(), ledger)
    };
    repeat_ledger_conformance::check_all(&make);
}
