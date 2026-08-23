use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::error::{Result, StateError};
use vortex_auth::ports::replay::ReplayGuard;
use vortex_auth::token::jti::Jti;
use vortex_auth::token::ttl::Ttl;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;

const DOMAIN: &str = "auth";
const SPENT: &str = "handoff-spent";

pub struct RedisReplayGuard {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisReplayGuard {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisReplayGuard { backbone, space }
    }

    fn spent_key(&self, jti: &Jti) -> String {
        self.space.member_key(SPENT, jti.as_str())
    }
}

impl ReplayGuard for RedisReplayGuard {
    fn seen(&self, jti: &Jti, _now: f64) -> Result<bool> {
        let key = self.spent_key(jti);
        self.backbone
            .execute(
                "поиск потраченного токена передачи",
                |pool| {
                    let key = key.clone();
                    async move { pool.exists::<i64, _>(key).await }
                },
            )
            .map(|found| found > 0)
            .map_err(|_| StateError::Unavailable)
    }

    fn remember_if_new(&self, jti: &Jti, ttl: Ttl, _now: f64) -> Result<bool> {
        let key = self.spent_key(jti);
        let seconds = ttl.as_seconds() as i64;

        self.backbone
            .execute(
                "запись потраченного токена передачи",
                move |pool| {
                    let key = key.clone();
                    async move {
                        pool.set::<Value, _, _>(
                            key,
                            1,
                            Some(Expiration::EX(seconds)),
                            Some(SetOptions::NX),
                            false,
                        )
                        .await
                    }
                },
            )
            .map(|answered| !answered.is_null())
            .map_err(|_| StateError::Unavailable)
    }
}
