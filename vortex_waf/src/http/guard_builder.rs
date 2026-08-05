//! Сборка стража со штатной проводкой зависимостей.

use crate::captcha::hmac_signer::HmacSigner;
use crate::captcha::hmac_verifier::HmacChallengeVerifier;
use crate::config::guard_config::GuardConfig;
use crate::engine::runtime::WafRuntime;
use crate::http::client_ip::peer_address::PeerAddressResolver;
use crate::http::client_ip::trusted_proxy::TrustedProxyResolver;
use crate::http::excluded_paths::ExcludedPaths;
use crate::http::guard::WafGuard;
use crate::http::request_factory::RequestFactory;
use crate::http::responses::blocked::BlockedResponseBuilder;
use crate::ports::challenge_verifier::ChallengeVerifier;
use crate::ports::clock::Clock;
use crate::ports::random_source::RandomSource;
use crate::random::os_random::OsRandom;
use crate::time::system_clock::SystemClock;
use std::sync::Arc;

pub struct GuardBuilder {
    runtime: Arc<WafRuntime>,
    config: GuardConfig,
    clock: Arc<dyn Clock>,
    random: Arc<dyn RandomSource>,
    excluded: ExcludedPaths,
    captcha: Option<Arc<dyn ChallengeVerifier>>,
    captcha_secret: String,
}

impl GuardBuilder {
    pub fn new(runtime: Arc<WafRuntime>) -> Self {
        GuardBuilder {
            runtime,
            config: GuardConfig::default(),
            clock: Arc::new(SystemClock::new()),
            random: Arc::new(OsRandom::new()),
            excluded: ExcludedPaths::default(),
            captcha: None,
            captcha_secret: String::new(),
        }
    }

    pub fn with_config(mut self, config: GuardConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_random(mut self, random: Arc<dyn RandomSource>) -> Self {
        self.random = random;
        self
    }

    pub fn with_excluded_paths(mut self, excluded: ExcludedPaths) -> Self {
        self.excluded = excluded;
        self
    }

    pub fn with_captcha_verifier(mut self, verifier: Arc<dyn ChallengeVerifier>) -> Self {
        self.captcha = Some(verifier);
        self
    }

    /// Секрет приложения для подписи капчи (см. `config::env`).
    pub fn with_captcha_secret(mut self, secret: impl Into<String>) -> Self {
        self.captcha_secret = secret.into();
        self
    }

    pub fn build(self) -> WafGuard {
        let ip_resolver = Arc::new(TrustedProxyResolver::new(
            self.config.trusted_proxies.clone(),
            Arc::new(PeerAddressResolver::new()),
        ));

        let captcha = self.captcha.unwrap_or_else(|| {
            let signer = Arc::new(HmacSigner::derive(
                &self.captcha_secret,
                "waf-captcha-v1",
                self.random.as_ref(),
            ));
            Arc::new(HmacChallengeVerifier::new(signer, self.clock.clone()))
        });

        WafGuard::new(
            self.runtime,
            RequestFactory::new(ip_resolver),
            self.excluded,
            captcha,
            BlockedResponseBuilder::new(self.clock.clone(), self.random.clone()),
            self.config,
        )
    }
}
