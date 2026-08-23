use std::sync::Arc;

use fred::prelude::*;
use vortex_ratelimit::antispam::digest::Digest;
use vortex_ratelimit::attempt::subject::Subject;
use vortex_ratelimit::attempt::window::Window;
use vortex_ratelimit::error::{CountError, Result};
use vortex_ratelimit::ports::repeat_ledger::RepeatLedger;
use vortex_ratelimit::ports::window_reset::WindowReset;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::ratelimit::attempt_limiter::RATELIMIT_DOMAIN;
use crate::ratelimit::scripts;

const SEQUENCE: &str = "antispam-sequence";

pub struct RedisRepeatLedger {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisRepeatLedger {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(RATELIMIT_DOMAIN);
        RedisRepeatLedger { backbone, space }
    }

    fn seen_key(&self, subject: &Subject) -> String {
        self.space.member_key(subject.bucket(), subject.member())
    }
}

impl RepeatLedger for RedisRepeatLedger {
    fn record(&self, subject: &Subject, digest: &Digest, window: Window, now: f64) -> Result<u32> {
        let seen_key = self.seen_key(subject);
        let sequence_key = self.space.key(SEQUENCE);
        let width = window.width();
        let digest = digest.as_str().to_owned();

        self.backbone
            .execute("счёт повторов сообщения", move |pool| {
                let keys = vec![seen_key.clone(), sequence_key.clone()];
                let args = vec![
                    now.to_string().into(),
                    width.to_string().into(),
                    digest.clone().into(),
                ];
                async move { scripts::REPEATS.run::<i64>(&pool, keys, args).await }
            })
            .map(|same| u32::try_from(same).unwrap_or(u32::MAX))
            .map_err(|_| CountError::Unavailable)
    }
}

impl WindowReset for RedisRepeatLedger {
    fn forget(&self, subject: &Subject) -> Result<()> {
        let seen_key = self.seen_key(subject);
        self.backbone
            .execute("сброс окна повторов", move |pool| {
                let seen_key = seen_key.clone();
                async move { pool.del::<i64, _>(seen_key).await }
            })
            .map(|_| ())
            .map_err(|_| CountError::Unavailable)
    }
}
