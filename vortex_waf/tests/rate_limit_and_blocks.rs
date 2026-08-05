//! Ограничение частоты, блокировки адресов и уборка состояния.

mod common;

use common::{has_rule, Harness};
use vortex_waf::config::EngineConfig;
use vortex_waf::domain::RequestBuilder;
use vortex_waf::ports::{BlockStore, IpBlocker, IpGate, StatsReporter};

fn request(ip: &str) -> vortex_waf::domain::InspectedRequest {
    RequestBuilder::new()
        .client_ip(ip)
        .path("/api/ping")
        .build()
}

#[test]
fn requests_beyond_the_limit_are_refused() {
    let waf = Harness::with_config(EngineConfig::default().rate_limit(3, 60));
    let req = request("198.51.100.1");

    for _ in 0..3 {
        assert!(!waf.runtime.analyze(&req).block);
    }
    let analysis = waf.runtime.analyze(&req);
    assert!(analysis.block);
    assert!(has_rule(&analysis, "RATE-LIMIT"));
    assert!(analysis.reason.unwrap().starts_with("Rate limit exceeded"));
}

#[test]
fn limit_resets_after_the_window() {
    let waf = Harness::with_config(EngineConfig::default().rate_limit(2, 60));
    let req = request("198.51.100.2");

    waf.runtime.analyze(&req);
    waf.runtime.analyze(&req);
    assert!(waf.runtime.analyze(&req).block);

    waf.clock.advance_secs(61);
    assert!(!waf.runtime.analyze(&req).block);
}

#[test]
fn whitelisted_address_is_never_limited() {
    let waf = Harness::with_config(EngineConfig::default().rate_limit(1, 60));
    let req = request("127.0.0.1");
    for _ in 0..10 {
        assert!(!waf.runtime.analyze(&req).block);
    }
}

#[test]
fn manually_blocked_address_is_refused_until_expiry() {
    let waf = Harness::new();
    let ip = "198.51.100.3".into();
    assert!(waf
        .runtime
        .reputation()
        .block(&ip, "ручная блокировка", 300));

    let analysis = waf.runtime.analyze(&request("198.51.100.3"));
    assert!(analysis.block);
    assert!(has_rule(&analysis, "IP-BLOCKED"));

    waf.clock.advance_secs(301);
    assert!(!waf.runtime.analyze(&request("198.51.100.3")).block);
}

#[test]
fn whitelisted_address_cannot_be_blocked() {
    let waf = Harness::new();
    let ip = "127.0.0.1".into();
    assert!(!waf.runtime.reputation().block(&ip, "попытка", 300));
    assert!(!waf.runtime.reputation().is_blocked(&ip));
}

#[test]
fn early_refusals_do_not_count_as_analyzed_requests() {
    let waf = Harness::new();
    let ip = "198.51.100.4".into();
    waf.runtime.reputation().block(&ip, "блок", 300);

    for _ in 0..5 {
        waf.runtime.analyze(&request("198.51.100.4"));
    }
    // Ранние отказы обходят стороной и правила, и счётчик запросов.
    assert_eq!(waf.stats.snapshot().total_requests, 0);
}

#[test]
fn maintenance_clears_expired_blocks() {
    let waf = Harness::new();
    waf.runtime
        .reputation()
        .block(&"198.51.100.5".into(), "блок", 60);
    waf.runtime
        .reputation()
        .block(&"198.51.100.6".into(), "блок", 3600);

    waf.clock.advance_secs(120);
    let reports = waf.runtime.run_maintenance();
    let removed: usize = reports.iter().map(|r| r.removed).sum();
    assert_eq!(removed, 1);
    assert_eq!(waf.runtime.block_store().len() as u64, 1);
}
