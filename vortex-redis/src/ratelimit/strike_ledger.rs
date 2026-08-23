use std::sync::Arc;

use fred::prelude::*;
use vortex_ratelimit::attempt::subject::Subject;
use vortex_ratelimit::error::Result;
use vortex_ratelimit::flood::memory::MemoryStrikeLedger;
use vortex_ratelimit::ports::strike_ledger::StrikeLedger;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::ratelimit::attempt_limiter::RATELIMIT_DOMAIN;

pub struct RedisStrikeLedger {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<MemoryStrikeLedger>,
    space: KeySpace,
}

impl RedisStrikeLedger {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(RATELIMIT_DOMAIN);
        RedisStrikeLedger {
            backbone,
            fallback: Arc::new(MemoryStrikeLedger::new()),
            space,
        }
    }

    pub fn fallback(&self) -> &Arc<MemoryStrikeLedger> {
        &self.fallback
    }

    fn strike_key(&self, subject: &Subject) -> String {
        self.space.member_key(subject.bucket(), subject.member())
    }
}

impl StrikeLedger for RedisStrikeLedger {
    fn strike(&self, subject: &Subject) -> Result<u32> {
        let strike_key = self.strike_key(subject);
        let counted =
            self.backbone
                .execute("счёт срабатываний флуда", move |pool| {
                    let strike_key = strike_key.clone();
                    async move { pool.incr::<i64, _>(strike_key).await }
                });

        match counted {
            Ok(strikes) => Ok(u32::try_from(strikes).unwrap_or(u32::MAX)),
            Err(_) => self.fallback.strike(subject),
        }
    }
}
