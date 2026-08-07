use crate::config::guard_config::GuardConfig;
use crate::engine::runtime::WafRuntime;
use crate::http::body_policy::BodyPolicy;
use crate::http::excluded_paths::ExcludedPaths;
use crate::http::outcome::GuardOutcome;
use crate::http::raw_request::RawHttpRequest;
use crate::http::request_factory::RequestFactory;
use crate::http::request_head::RequestHead;
use crate::http::responses::{blocked::BlockedResponseBuilder, captcha_required, too_large};
use crate::ports::challenge_verifier::ChallengeVerifier;
use std::sync::Arc;

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

    pub fn plan(&self, head: &RequestHead) -> BodyPolicy {
        if self.excluded.contains(&head.path) {
            return BodyPolicy::Skip;
        }
        if head.declared_length() > self.config.max_body_bytes {
            return BodyPolicy::reject(too_large::build(self.config.max_body_bytes));
        }
        if !head.declares_body() {
            return BodyPolicy::InspectHead;
        }
        BodyPolicy::BufferBody {
            limit: self.config.max_body_bytes,
        }
    }

    pub fn evaluate(&self, raw: &RawHttpRequest) -> GuardOutcome {
        if self.excluded.contains(&raw.path) {
            return GuardOutcome::Pass;
        }

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

    pub fn max_body_bytes(&self) -> usize {
        self.config.max_body_bytes
    }
}
