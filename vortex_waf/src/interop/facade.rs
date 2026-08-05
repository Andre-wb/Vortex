//! Фасад над собранным WAF в примитивных типах.
//!
//! Всё, что нужно вызывающей стороне за пределами Rust, собрано в одном месте и
//! не требует знания трейтов крейта. Языковая привязка поверх него остаётся
//! тонкой: разобрать аргументы, вызвать метод, отдать результат.

use crate::captcha::arithmetic_issuer::ArithmeticChallengeIssuer;
use crate::captcha::hmac_signer::HmacSigner;
use crate::captcha::hmac_verifier::HmacChallengeVerifier;
use crate::config::engine_config::EngineConfig;
use crate::domain::client_ip::ClientIp;
use crate::engine::builder::WafBuilder;
use crate::engine::reporting::build_report;
use crate::engine::runtime::WafRuntime;
use crate::error::Result;
use crate::http::client_ip::peer_address::PeerAddressResolver;
use crate::http::client_ip::trusted_proxy::TrustedProxyResolver;
use crate::interop::config_spec::ConfigSpec;
use crate::interop::finding_map::AnalysisView;
use crate::interop::request_spec::RequestSpec;
use crate::interop::stats_view::StatsView;
use crate::manager::dto::{BlockedIpView, RuleView};
use crate::manager::waf_manager::WafManager;
use crate::ports::challenge_issuer::ChallengeIssuer;
use crate::ports::challenge_verifier::ChallengeVerifier;
use crate::ports::client_ip_resolver::ClientIpResolver;
use crate::ports::ip_deny_list::IpDenyList;
use crate::ports::ip_gate::IpGate;
use crate::random::os_random::OsRandom;
use crate::time::system_clock::SystemClock;
use std::sync::Arc;

pub struct WafFacade {
    runtime: Arc<WafRuntime>,
    manager: WafManager,
    issuer: ArithmeticChallengeIssuer,
    verifier: HmacChallengeVerifier,
}

impl WafFacade {
    pub fn new(spec: &ConfigSpec) -> Result<WafFacade> {
        let runtime = Arc::new(
            WafBuilder::new()
                .with_config(spec.to_engine_config())
                .build()?,
        );
        let clock = Arc::new(SystemClock::new());
        let random = Arc::new(OsRandom::new());
        let signer = Arc::new(HmacSigner::derive(
            spec.captcha_secret.as_deref().unwrap_or(""),
            "waf-captcha-v1",
            random.as_ref(),
        ));

        Ok(WafFacade {
            manager: WafManager::new(Arc::clone(&runtime)),
            issuer: ArithmeticChallengeIssuer::new(
                Arc::clone(&signer) as Arc<_>,
                clock.clone(),
                random,
            ),
            verifier: HmacChallengeVerifier::new(signer, clock),
            runtime,
        })
    }

    pub fn analyze(&self, spec: RequestSpec) -> AnalysisView {
        AnalysisView::from(&self.runtime.analyze(&spec.into_request()))
    }

    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        self.runtime.reputation().is_blocked(&ClientIp::from(ip))
    }

    pub fn block_ip(&self, ip: &str, reason: &str, duration_secs: u64) -> bool {
        self.manager.block_ip(ip, reason, duration_secs).success
    }

    pub fn unblock_ip(&self, ip: &str) -> bool {
        self.manager.unblock_ip(ip).success
    }

    pub fn blocked_ips(&self) -> Vec<BlockedIpView> {
        self.manager.blocked_ips()
    }

    pub fn add_whitelist_ip(&self, ip: &str) -> bool {
        self.manager.add_whitelist_ip(ip).success
    }

    pub fn remove_whitelist_ip(&self, ip: &str) -> bool {
        self.manager.remove_whitelist_ip(ip).success
    }

    pub fn whitelist(&self) -> Vec<String> {
        self.manager.whitelist()
    }

    pub fn add_blacklist_ip(&self, ip: &str) -> bool {
        self.runtime.deny_list().add(ClientIp::from(ip))
    }

    pub fn remove_blacklist_ip(&self, ip: &str) -> bool {
        self.runtime.deny_list().remove(&ClientIp::from(ip))
    }

    pub fn blacklist(&self) -> Vec<String> {
        self.runtime
            .deny_list()
            .list()
            .into_iter()
            .map(|ip| ip.to_string())
            .collect()
    }

    pub fn stats(&self) -> StatsView {
        StatsView::from(&build_report(&self.runtime))
    }

    pub fn rules(&self) -> Vec<RuleView> {
        self.manager.rules()
    }

    /// Уборка просроченных блокировок и неактивной истории обращений.
    /// Возвращает число удалённых записей.
    pub fn run_maintenance(&self) -> usize {
        self.runtime
            .run_maintenance()
            .iter()
            .map(|report| report.removed)
            .sum()
    }

    /// Новая задача-капча: идентификатор, вопрос, срок жизни в секундах.
    pub fn issue_captcha(&self, client_ip: &str) -> (String, String, u64) {
        let challenge = self.issuer.issue(&ClientIp::from(client_ip));
        (
            challenge.challenge_id,
            challenge.question,
            challenge.expires_in,
        )
    }

    pub fn verify_captcha(&self, challenge_id: &str, answer: &str) -> bool {
        self.verifier.verify(challenge_id, answer)
    }

    pub fn config(&self) -> &EngineConfig {
        self.runtime.config()
    }

    pub fn rule_count(&self) -> usize {
        self.runtime.scanner().rules().len()
    }
}

/// Адрес источника с учётом доверенных прокси.
///
/// Пустой список доверенных сетей означает, что заголовки пересылки
/// игнорируются целиком и берётся адрес TCP-пира.
pub fn resolve_client_ip(
    peer: Option<&str>,
    headers: &[(String, String)],
    trusted_proxies: &[String],
) -> String {
    let mut map = crate::domain::header_map::HeaderMap::new();
    for (name, value) in headers {
        map.insert(name, value.clone());
    }
    let resolver = TrustedProxyResolver::new(trusted_proxies, Arc::new(PeerAddressResolver::new()));
    resolver.resolve(peer, &map).to_string()
}

#[cfg(test)]
mod tests {
    use super::{resolve_client_ip, WafFacade};
    use crate::interop::config_spec::ConfigSpec;
    use crate::interop::request_spec::RequestSpec;

    fn facade() -> WafFacade {
        WafFacade::new(&ConfigSpec {
            rate_limit_requests: Some(10_000),
            ..Default::default()
        })
        .expect("фасад собрался")
    }

    fn attack() -> RequestSpec {
        RequestSpec {
            client_ip: Some("203.0.113.5".to_owned()),
            method: Some("GET".to_owned()),
            path: Some("/api/search".to_owned()),
            params: vec![("q".to_owned(), "1' OR 1=1 -- ".to_owned())],
            ..Default::default()
        }
    }

    #[test]
    fn analyze_reports_a_block() {
        let view = facade().analyze(attack());
        assert!(view.block);
        assert_eq!(view.client_ip, "203.0.113.5");
        assert!(!view.matched_rules.is_empty());
        assert!(view.findings.iter().all(|f| f.contains_key("rule_id")));
    }

    #[test]
    fn clean_request_passes() {
        let spec = RequestSpec {
            client_ip: Some("203.0.113.6".to_owned()),
            method: Some("GET".to_owned()),
            path: Some("/api/chat/messages".to_owned()),
            headers: vec![("user-agent".to_owned(), "Mozilla/5.0".to_owned())],
            ..Default::default()
        };
        assert!(!facade().analyze(spec).block);
    }

    #[test]
    fn block_and_unblock_round_trip() {
        let facade = facade();
        assert!(facade.block_ip("198.51.100.1", "тест", 60));
        assert!(facade.is_ip_blocked("198.51.100.1"));
        assert_eq!(facade.blocked_ips().len(), 1);
        assert!(facade.unblock_ip("198.51.100.1"));
        assert!(!facade.is_ip_blocked("198.51.100.1"));
    }

    #[test]
    fn whitelisted_ip_cannot_be_blocked() {
        let facade = facade();
        assert!(!facade.block_ip("127.0.0.1", "тест", 60));
        assert!(facade.whitelist().contains(&"127.0.0.1".to_owned()));
    }

    #[test]
    fn blacklist_blocks_immediately() {
        let facade = facade();
        assert!(facade.add_blacklist_ip("6.6.6.6"));
        assert!(facade.is_ip_blocked("6.6.6.6"));
        assert!(facade.blacklist().contains(&"6.6.6.6".to_owned()));
        assert!(facade.remove_blacklist_ip("6.6.6.6"));
        assert!(!facade.is_ip_blocked("6.6.6.6"));
    }

    #[test]
    fn stats_and_rules_are_exposed() {
        let facade = facade();
        facade.analyze(attack());
        let stats = facade.stats();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.blocked_requests, 1);
        assert_eq!(stats.block_rate, 100.0);
        assert_eq!(facade.rules().len(), 74);
        assert_eq!(facade.rule_count(), 74);
        assert!(facade.rules().iter().any(|r| r.trigger_count > 0));
    }

    #[test]
    fn captcha_round_trip() {
        let facade = facade();
        let (id, question, ttl) = facade.issue_captcha("203.0.113.9");
        assert!(question.starts_with("What is "));
        assert_eq!(ttl, 300);
        assert!(!facade.verify_captcha(&id, "заведомо неверно"));
        assert!(!facade.verify_captcha("мусор", "7"));
    }

    #[test]
    fn maintenance_is_callable() {
        let facade = facade();
        facade.block_ip("198.51.100.2", "тест", 3600);
        // Блокировка ещё активна — удалять нечего.
        assert_eq!(facade.run_maintenance(), 0);
    }

    #[test]
    fn config_is_readable() {
        let facade = WafFacade::new(&ConfigSpec {
            rate_limit_requests: Some(42),
            block_duration: Some(120),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(facade.config().rate_limit_requests, 42);
        assert_eq!(facade.config().block_duration_secs, 120);
    }

    #[test]
    fn client_ip_ignores_headers_without_trusted_proxies() {
        let headers = vec![("x-forwarded-for".to_owned(), "1.2.3.4".to_owned())];
        assert_eq!(
            resolve_client_ip(Some("203.0.113.7"), &headers, &[]),
            "203.0.113.7"
        );
        assert_eq!(
            resolve_client_ip(Some("10.0.0.5"), &headers, &["10.0.0.0/8".to_owned()]),
            "1.2.3.4"
        );
    }
}
