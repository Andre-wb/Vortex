use std::sync::Arc;

use fred::prelude::*;
use vortex_delivery::dedup::limits;
use vortex_delivery::error::{Result, StateError};
use vortex_delivery::message::identifier::MessageId;
use vortex_delivery::ports::seen_messages::SeenMessages;

use crate::backbone::RedisBackbone;
use crate::delivery::scripts::{self, REMEMBER};
use crate::keys::KeySpace;

const SEEN: &str = "seen";

pub struct RedisSeenMessages {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
    capacity: usize,
    lifetime: f64,
}

impl RedisSeenMessages {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        Self::sized(backbone, limits::CAPACITY, limits::LIFETIME_SECONDS)
    }

    pub fn sized(backbone: Arc<RedisBackbone>, capacity: usize, lifetime: f64) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisSeenMessages {
            backbone,
            space,
            capacity,
            lifetime,
        }
    }

    fn seen_key(&self) -> String {
        self.space.key(SEEN)
    }
}

impl SeenMessages for RedisSeenMessages {
    fn remember(&self, message: &MessageId, now: f64) -> Result<bool> {
        let key = self.seen_key();
        let member = message.written().to_owned();
        let lifetime = self.lifetime;
        let capacity = self.capacity as i64;

        let verdict = self
            .backbone
            .execute("память о повторах", move |pool| {
                let keys = vec![key.clone()];
                let args: Vec<Value> = vec![
                    now.into(),
                    lifetime.into(),
                    capacity.into(),
                    member.clone().into(),
                ];
                async move { REMEMBER.run::<i64>(&pool, keys, args).await }
            })
            .map_err(|_| StateError::Unavailable)?;

        Ok(verdict == 1)
    }

    fn count(&self) -> Result<usize> {
        let key = self.seen_key();
        let counted = self
            .backbone
            .execute(
                "размер памяти о повторах",
                move |pool| {
                    let key = key.clone();
                    async move { pool.zcard::<u64, _>(key).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(counted as usize)
    }
}
