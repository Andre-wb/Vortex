mod support;

use std::sync::Arc;

use vortex_ratelimit::attempt::limit::Limit;
use vortex_ratelimit::attempt::subject::Subject;
use vortex_ratelimit::attempt::window::Window;
use vortex_ratelimit::ports::attempt_limiter::AttemptLimiter;
use vortex_ratelimit::ports::repeat_ledger::RepeatLedger;
use vortex_ratelimit::ports::strike_ledger::StrikeLedger;
use vortex_ratelimit::ports::window_reset::WindowReset;
use vortex_ratelimit::testing::{
    attempt_limiter_conformance, repeat_ledger_conformance, strike_ledger_conformance,
    window_reset_conformance,
};
use vortex_redis::ratelimit::attempt_limiter::RedisAttemptLimiter;
use vortex_redis::ratelimit::flood_window::RedisFloodWindow;
use vortex_redis::ratelimit::repeat_ledger::RedisRepeatLedger;
use vortex_redis::ratelimit::strike_ledger::RedisStrikeLedger;

#[test]
fn the_redis_attempt_limiter_of_the_auth_domain_satisfies_the_port_contract() {
    if support::backbone(&support::unique_prefix("attempts-probe")).is_none() {
        eprintln!("Redis недоступен — проверка счёта попыток аутентификации пропущена");
        return;
    }
    let make = || -> Arc<dyn AttemptLimiter> {
        let prefix = support::unique_prefix("attempts");
        Arc::new(RedisAttemptLimiter::for_auth(
            support::backbone(&prefix).unwrap(),
        ))
    };
    attempt_limiter_conformance::check_all(&make);
}

#[test]
fn the_redis_attempt_limiter_of_the_rate_limit_domain_satisfies_the_port_contract() {
    if support::backbone(&support::unique_prefix("limits-probe")).is_none() {
        eprintln!("Redis недоступен — проверка счёта обращений пропущена");
        return;
    }
    let make = || -> Arc<dyn AttemptLimiter> {
        let prefix = support::unique_prefix("limits");
        Arc::new(RedisAttemptLimiter::for_rate_limits(
            support::backbone(&prefix).unwrap(),
        ))
    };
    attempt_limiter_conformance::check_all(&make);
}

#[test]
fn the_two_domains_never_share_one_window() {
    let prefix = support::unique_prefix("domains");
    let Some(backbone) = support::backbone(&prefix) else {
        eprintln!("Redis недоступен — проверка разделения доменов пропущена");
        return;
    };
    let auth = RedisAttemptLimiter::for_auth(backbone.clone());
    let limits = RedisAttemptLimiter::for_rate_limits(backbone);
    let subject = Subject::of("entry-attempts", "10.0.0.1");
    let limit = Limit::of(1).unwrap();
    let window = Window::seconds(60).unwrap();

    assert!(auth.allow(&subject, limit, window, 1_000.0).unwrap());
    assert!(!auth.allow(&subject, limit, window, 1_000.0).unwrap());
    assert!(limits.allow(&subject, limit, window, 1_000.0).unwrap());
}

#[test]
fn the_redis_flood_window_satisfies_the_attempt_limiter_contract() {
    if support::backbone(&support::unique_prefix("flood-probe")).is_none() {
        eprintln!("Redis недоступен — проверка окна флуд-контроля пропущена");
        return;
    }
    let make = || -> Arc<dyn AttemptLimiter> {
        let prefix = support::unique_prefix("flood");
        Arc::new(RedisFloodWindow::new(support::backbone(&prefix).unwrap()))
    };
    attempt_limiter_conformance::check_all(&make);
}

#[test]
fn forgetting_a_redis_flood_window_satisfies_the_port_contract() {
    if support::backbone(&support::unique_prefix("flood-reset-probe")).is_none() {
        eprintln!("Redis недоступен — проверка сброса окна флуд-контроля пропущена");
        return;
    }
    let make = || -> (Arc<dyn AttemptLimiter>, Arc<dyn WindowReset>) {
        let prefix = support::unique_prefix("flood-reset");
        let window = Arc::new(RedisFloodWindow::new(support::backbone(&prefix).unwrap()));
        (window.clone(), window)
    };
    window_reset_conformance::check_all(&make);
}

#[test]
fn the_redis_strike_ledger_satisfies_the_port_contract() {
    if support::backbone(&support::unique_prefix("strikes-probe")).is_none() {
        eprintln!("Redis недоступен — проверка счёта срабатываний флуда пропущена");
        return;
    }
    let make = || -> Arc<dyn StrikeLedger> {
        let prefix = support::unique_prefix("strikes");
        Arc::new(RedisStrikeLedger::new(support::backbone(&prefix).unwrap()))
    };
    strike_ledger_conformance::check_all(&make);
}

#[test]
fn a_strike_recorded_in_redis_outlives_the_window_that_earned_it() {
    let prefix = support::unique_prefix("strikes-life");
    let Some(backbone) = support::backbone(&prefix) else {
        eprintln!("Redis недоступен — проверка срока жизни страйка пропущена");
        return;
    };
    let ledger = RedisStrikeLedger::new(backbone.clone());
    let window = RedisFloodWindow::new(backbone);
    let member = Subject::of("flood-strikes", "6300:1");
    let counted = Subject::of("flood-window", "6300:1");

    assert_eq!(ledger.strike(&member).unwrap(), 1);
    window.forget(&counted).unwrap();
    assert_eq!(ledger.strike(&member).unwrap(), 2);
}

#[test]
fn the_redis_repeat_ledger_satisfies_the_port_contract() {
    if support::backbone(&support::unique_prefix("repeats-probe")).is_none() {
        eprintln!("Redis недоступен — проверка счёта повторов пропущена");
        return;
    }
    let make = || -> (Arc<dyn RepeatLedger>, Arc<dyn WindowReset>) {
        let prefix = support::unique_prefix("repeats");
        let ledger = Arc::new(RedisRepeatLedger::new(support::backbone(&prefix).unwrap()));
        (ledger.clone(), ledger)
    };
    repeat_ledger_conformance::check_all(&make);
}

#[test]
fn forgetting_a_window_of_the_rate_limit_domain_satisfies_the_port_contract() {
    if support::backbone(&support::unique_prefix("limits-reset-probe")).is_none() {
        eprintln!("Redis недоступен — проверка сброса окна обращений пропущена");
        return;
    }
    let make = || -> (Arc<dyn AttemptLimiter>, Arc<dyn WindowReset>) {
        let prefix = support::unique_prefix("limits-reset");
        let limiter = Arc::new(RedisAttemptLimiter::for_rate_limits(
            support::backbone(&prefix).unwrap(),
        ));
        (limiter.clone(), limiter)
    };
    window_reset_conformance::check_all(&make);
}
