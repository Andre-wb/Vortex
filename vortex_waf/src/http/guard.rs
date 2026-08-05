//! Транспортный страж: порядок проверок перед передачей запроса приложению.
//!
//! Аналог прежнего ASGI-middleware, но без привязки к конкретному фреймворку:
//! на вход — описание запроса, на выходе — «пропустить» или готовый ответ.

use crate::config::guard_config::GuardConfig;
use crate::engine::runtime::WafRuntime;
use crate::http::excluded_paths::ExcludedPaths;
use crate::http::outcome::GuardOutcome;
use crate::http::raw_request::RawHttpRequest;
use crate::http::request_factory::RequestFactory;
use crate::http::responses::{blocked::BlockedResponseBuilder, captcha_required, too_large};
use crate::ports::challenge_verifier::ChallengeVerifier;
use std::sync::Arc;

/// Заголовки, которыми клиент передаёт решённую капчу.
pub const CAPTCHA_ID_HEADER: &str = "x-captcha-id";
pub const CAPTCHA_ANSWER_HEADER: &str = "x-captcha-answer";

pub struct WafGuard {
    runtime: Arc<WafRuntime>,
    factory: RequestFactory,
    excluded: ExcludedPaths,
    captcha: Arc<dyn ChallengeVerifier>,
    blocked_response: BlockedResponseBuilder,
    config: GuardConfig,
}

impl WafGuard {
    pub fn new(
        runtime: Arc<WafRuntime>,
        factory: RequestFactory,
        excluded: ExcludedPaths,
        captcha: Arc<dyn ChallengeVerifier>,
        blocked_response: BlockedResponseBuilder,
        config: GuardConfig,
    ) -> Self {
        WafGuard {
            runtime,
            factory,
            excluded,
            captcha,
            blocked_response,
            config,
        }
    }

    pub fn evaluate(&self, raw: &RawHttpRequest) -> GuardOutcome {
        // Исключённые пути не анализируем и тело не буферизуем.
        if self.excluded.contains(&raw.path) {
            return GuardOutcome::Pass;
        }

        // Размер проверяется по заявленному Content-Length и по факту: одно
        // прикрывает другое, если заголовок соврал или его нет.
        if raw.declared_length() > self.config.max_body_bytes
            || raw.body.len() > self.config.max_body_bytes
        {
            return GuardOutcome::reject(too_large::build(self.config.max_body_bytes));
        }

        let request = self.factory.build(raw);
        let analysis = self.runtime.analyze(&request);
        if analysis.block {
            return GuardOutcome::reject(self.blocked_response.build(&analysis));
        }

        // Капча проверяется только если клиент сам её прислал.
        if let (Some(id), Some(answer)) = (
            request.header(CAPTCHA_ID_HEADER),
            request.header(CAPTCHA_ANSWER_HEADER),
        ) {
            if !self.captcha.verify(id, answer) {
                return GuardOutcome::reject(captcha_required::build());
            }
        }

        GuardOutcome::Pass
    }

    pub fn runtime(&self) -> &Arc<WafRuntime> {
        &self.runtime
    }

    pub fn excluded_paths(&self) -> &ExcludedPaths {
        &self.excluded
    }
}
