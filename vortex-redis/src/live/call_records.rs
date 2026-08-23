use std::sync::Arc;

use fred::prelude::*;
use vortex_live::call::call_id::CallId;
use vortex_live::call::record::Call;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::call_records::CallRecords;
use vortex_live::store::swapped::Swapped;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left, SWAP_KEEPING_LIFE};

const CALL: &str = "call";

pub struct RedisCallRecords {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisCallRecords {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisCallRecords { backbone, space }
    }

    fn call_key(&self, call: &CallId) -> String {
        self.space.member_key(CALL, call.as_str())
    }

    fn read(&self, call: &CallId) -> Result<Option<(String, Call)>> {
        let key = self.call_key(call);
        let stored = self
            .backbone
            .execute("чтение звонка", move |pool| {
                let key = key.clone();
                async move { pool.get::<Option<String>, _>(key).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(stored.and_then(|raw| Call::parse(&raw).map(|record| (raw, record))))
    }
}

impl CallRecords for RedisCallRecords {
    fn open(&self, call: &Call, now: f64) -> Result<()> {
        let Ok(identifier) = CallId::parse(&call.call_id) else {
            return Err(StateError::Unavailable);
        };
        let key = self.call_key(&identifier);
        let wire = call.to_wire();
        let life = seconds_left(call.until, now);
        self.backbone
            .execute("создание звонка", move |pool| {
                let key = key.clone();
                let wire = wire.clone();
                async move {
                    pool.set::<(), _, _>(key, wire, Some(Expiration::EX(life)), None, false)
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)
    }

    fn find(&self, call: &CallId, now: f64) -> Result<Option<Call>> {
        Ok(self
            .read(call)?
            .map(|(_, record)| record)
            .filter(|record| record.until > now))
    }

    fn swap(
        &self,
        call: &CallId,
        expected: &Call,
        replacement: &Call,
        now: f64,
    ) -> Result<Swapped> {
        let Some((raw, held)) = self.read(call)? else {
            return Ok(Swapped::Missing);
        };
        if held.until <= now {
            return Ok(Swapped::Missing);
        }
        if &held != expected {
            return Ok(Swapped::Changed);
        }

        let key = self.call_key(call);
        let wire = replacement.to_wire();
        let life = seconds_left(replacement.until, now);
        let outcome = self
            .backbone
            .execute("замена звонка", move |pool| {
                let key = key.clone();
                let raw = raw.clone();
                let wire = wire.clone();
                async move {
                    SWAP_KEEPING_LIFE
                        .run::<i64>(&pool, vec![key], vec![raw.into(), wire.into(), life.into()])
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;

        Ok(match outcome {
            scripts::SWAPPED => Swapped::Done,
            scripts::CHANGED => Swapped::Changed,
            _ => Swapped::Missing,
        })
    }

    fn forget(&self, call: &CallId, now: f64) -> Result<bool> {
        let held = self.read(call)?.filter(|(_, record)| record.until > now);
        let key = self.call_key(call);
        let dropped = self
            .backbone
            .execute("удаление звонка", move |pool| {
                let key = key.clone();
                async move { pool.del::<i64, _>(key).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(dropped > 0 && held.is_some())
    }
}
