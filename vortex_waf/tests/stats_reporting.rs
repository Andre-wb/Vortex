//! Статистика и управляющее API.

mod common;

use common::Harness;
use std::sync::Arc;
use vortex_waf::domain::RequestBuilder;
use vortex_waf::manager::WafManager;

fn attack(ip: &str) -> vortex_waf::domain::InspectedRequest {
    RequestBuilder::new()
        .client_ip(ip)
        .path("/api/search")
        .query("q=1%27+OR+1%3D1+--+")
        .build()
}

fn clean(ip: &str) -> vortex_waf::domain::InspectedRequest {
    RequestBuilder::new()
        .client_ip(ip)
        .path("/api/chat/messages")
        .header("user-agent", "Mozilla/5.0")
        .build()
}

#[test]
fn report_counts_requests_and_blocks() {
    let waf = Harness::new();
    waf.runtime.analyze(&attack("203.0.113.50"));
    waf.runtime.analyze(&clean("203.0.113.51"));
    waf.runtime.analyze(&clean("203.0.113.52"));
    waf.runtime.analyze(&clean("203.0.113.53"));

    let manager = WafManager::new(Arc::clone(&waf.runtime));
    let report = manager.stats();
    assert_eq!(report.total_requests, 4);
    assert_eq!(report.blocked_requests, 1);
    assert_eq!(report.block_rate, 25.0);
    assert!(!report.rules_triggered.is_empty());
    assert!(report.active_rules > 0);
}

#[test]
fn rule_view_shows_trigger_counts_separately_from_blocks() {
    let waf = Harness::new();
    waf.runtime.analyze(&attack("203.0.113.54"));

    let manager = WafManager::new(Arc::clone(&waf.runtime));
    let rules = manager.rules();
    assert_eq!(rules.len(), 74);

    let triggered: Vec<_> = rules.iter().filter(|r| r.trigger_count > 0).collect();
    assert!(!triggered.is_empty());
    assert!(triggered.iter().all(|r| r.last_triggered.is_some()));
}

#[test]
fn manager_manages_blocks_and_whitelist() {
    let waf = Harness::new();
    let manager = WafManager::new(Arc::clone(&waf.runtime));

    let blocked = manager.block_ip("198.51.100.10", "спам", 600);
    assert!(blocked.success);
    assert_eq!(manager.blocked_ips().len(), 1);
    assert_eq!(manager.blocked_ips()[0].duration, 600);

    assert!(manager.unblock_ip("198.51.100.10").success);
    assert!(!manager.unblock_ip("198.51.100.10").success);
    assert!(manager.blocked_ips().is_empty());

    assert!(manager.add_whitelist_ip("10.0.0.7").success);
    assert!(manager.whitelist().contains(&"10.0.0.7".to_owned()));
    assert!(manager.remove_whitelist_ip("10.0.0.7").success);

    // Некорректный адрес в белый список не попадает.
    let invalid = manager.add_whitelist_ip("не-адрес");
    assert!(!invalid.success);
    assert_eq!(invalid.message.as_deref(), Some("Invalid IP format"));
}

#[test]
fn blocked_ip_view_serializes_timestamps() {
    let waf = Harness::new();
    let manager = WafManager::new(Arc::clone(&waf.runtime));
    manager.block_ip("198.51.100.11", "спам", 60);

    let view = &manager.blocked_ips()[0];
    assert_eq!(view.blocked_at, "2026-01-01T00:00:00+00:00");
    assert_eq!(view.blocked_until, "2026-01-01T00:01:00+00:00");
}
