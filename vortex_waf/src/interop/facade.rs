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
use crate::http::guard::WafGuard;
use crate::http::guard_builder::GuardBuilder;
use crate::interop::config_spec::ConfigSpec;
use crate::interop::finding_map::AnalysisView;
use crate::interop::guard_spec::GuardSpec;
use crate::interop::request_spec::RequestSpec;
use crate::interop::stats_view::StatsView;
use crate::manager::dto::{BlockedIpView, RuleView};
use crate::manager::waf_manager::WafManager;
use crate::ports::challenge_issuer::ChallengeIssuer;
use crate::ports::challenge_verifier::ChallengeVerifier;
use crate::ports::client_ip_resolver::ClientIpResolver;
use crate::ports::clock::Clock;
use crate::ports::ip_deny_list::IpDenyList;
use crate::ports::ip_gate::IpGate;
use crate::random::os_random::OsRandom;
use crate::redis::block_store::RedisBlockStore;
use crate::redis::request_history::RedisRequestHistory;
use crate::time::system_clock::SystemClock;
use std::sync::Arc;

pub struct WafFacade {
    runtime: Arc<WafRuntime>,
    manager: WafManager,
    issuer: ArithmeticChallengeIssuer,
    verifier: Arc<HmacChallengeVerifier>,
    clock: Arc<dyn Clock>,
}

impl WafFacade {
    pub fn new(spec: &ConfigSpec) -> Result<WafFacade> {
        let clock = Arc::new(SystemClock::new());
        let mut builder = WafBuilder::new()
            .with_config(spec.to_engine_config())
            .with_clock(clock.clone());

        // Общее состояние подключается до сборки: блокировки и история обращений
        // должны действовать во всех воркерах, а не только в том, где записаны.
        if let Some(backbone) = crate::redis::shared::backbone() {
            builder = builder
                .with_block_store(Arc::new(RedisBlockStore::new(
                    backbone.clone(),
                    clock.clone(),
                )))
                .with_request_history(Arc::new(RedisRequestHistory::new(backbone)));
        }

        let runtime = Arc::new(builder.build()?);
        let random = Arc::new(OsRandom::new());
        let signer = Arc::new(HmacSigner::derive(
            &spec.resolve_captcha_secret(),
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
            verifier: Arc::new(HmacChallengeVerifier::new(signer, clock.clone())),
            runtime,
            clock,
        })
    }

    pub fn guard(&self, spec: &GuardSpec) -> WafGuard {
        GuardBuilder::new(Arc::clone(&self.runtime))
            .with_config(spec.to_guard_config())
            .with_excluded_paths(spec.to_excluded_paths())
            .with_clock(self.clock.clone())
            .with_captcha_verifier(self.verifier.clone())
            .build()
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

    pub fn run_maintenance(&self) -> usize {
        self.runtime
            .run_maintenance()
            .iter()
            .map(|report| report.removed)
            .sum()
    }

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
    use crate::http::guard::{CAPTCHA_ANSWER_HEADER, CAPTCHA_ID_HEADER};
    use crate::http::raw_request::RawHttpRequest;
    use crate::interop::config_spec::ConfigSpec;
    use crate::interop::guard_spec::GuardSpec;
    use crate::interop::request_spec::RequestSpec;

    fn facade() -> WafFacade {
        WafFacade::new(&ConfigSpec {
            rate_limit_requests: Some(10_000),
            ..Default::default()
        })
        .expect("фасад собрался")
    }

    fn facade_with_secret(secret: &str) -> WafFacade {
        WafFacade::new(&ConfigSpec {
            rate_limit_requests: Some(10_000),
            captcha_secret: Some(secret.to_owned()),
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
    fn the_guard_verifies_captcha_issued_by_the_engine() {
        let facade = facade();
        let (id, question, _) = facade.issue_captcha("203.0.113.10");
        let answer = solve(&question);
        let guard = facade.guard(&GuardSpec::default());

        let base = RawHttpRequest::get("/api/chat/messages")
            .with_peer("203.0.113.10")
            .with_header(CAPTCHA_ID_HEADER, &id);

        let wrong = base
            .clone()
            .with_header(CAPTCHA_ANSWER_HEADER, &format!("{}", answer + 1));
        assert_eq!(guard.evaluate(&wrong).status(), Some(429));

        let correct = base.with_header(CAPTCHA_ANSWER_HEADER, &answer.to_string());
        assert!(guard.evaluate(&correct).is_pass());
    }

    #[test]
    fn a_shared_secret_makes_captcha_valid_across_engines() {
        let issuing = facade_with_secret("общий секрет воркеров");
        let checking = facade_with_secret("общий секрет воркеров");
        let (id, question, _) = issuing.issue_captcha("203.0.113.21");
        let answer = solve(&question).to_string();

        assert!(checking.verify_captcha(&id, &answer));

        let solved = RawHttpRequest::get("/api/chat/messages")
            .with_peer("203.0.113.21")
            .with_header(CAPTCHA_ID_HEADER, &id)
            .with_header(CAPTCHA_ANSWER_HEADER, &answer);
        assert!(checking
            .guard(&GuardSpec::default())
            .evaluate(&solved)
            .is_pass());
    }

    #[test]
    fn engines_with_different_secrets_reject_each_others_captcha() {
        let issuing = facade_with_secret("секрет A");
        let checking = facade_with_secret("секрет B");
        let (id, question, _) = issuing.issue_captcha("203.0.113.22");

        assert!(!checking.verify_captcha(&id, &solve(&question).to_string()));
    }

    fn solve(question: &str) -> i64 {
        let expression = question
            .trim_start_matches("What is ")
            .trim_end_matches('?')
            .trim();
        let (left, operator, right) = match expression.split_whitespace().collect::<Vec<_>>()[..] {
            [left, operator, right] => (left, operator, right),
            _ => panic!("непонятный вопрос капчи: {question}"),
        };
        let left: i64 = left.parse().expect("левый операнд");
        let right: i64 = right.parse().expect("правый операнд");
        match operator {
            "+" => left + right,
            "-" => left - right,
            "*" => left * right,
            _ => panic!("непонятная операция: {operator}"),
        }
    }

    #[test]
    fn the_guard_shares_the_engine_state() {
        let facade = facade();
        let guard = facade.guard(&GuardSpec::default());
        facade.add_blacklist_ip("198.51.100.7");

        let raw = RawHttpRequest::get("/api/chat/messages").with_peer("198.51.100.7");
        assert_eq!(guard.evaluate(&raw).status(), Some(403));
    }

    #[test]
    fn maintenance_is_callable() {
        let facade = facade();
        facade.block_ip("198.51.100.2", "тест", 3600);
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
