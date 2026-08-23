use std::sync::Arc;

use fred::prelude::*;
use vortex_live::call::call_id::CallId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::ring_claims::RingClaims;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left};

const RING: &str = "ring";
const RUNG: &str = "rung";

pub struct RedisRingClaims {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisRingClaims {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisRingClaims { backbone, space }
    }

    fn ring_key(&self, call: &CallId) -> String {
        self.space.member_key(RING, call.as_str())
    }
}

impl RingClaims for RedisRingClaims {
    fn claim(&self, call: &CallId, until: f64, now: f64) -> Result<bool> {
        let key = self.ring_key(call);
        let life = seconds_left(until, now);
        let taken = self
            .backbone
            .execute(
                "захват срабатывания дозвона",
                move |pool| {
                    let key = key.clone();
                    async move {
                        pool.set::<Option<String>, _, _>(
                            key,
                            RUNG,
                            Some(Expiration::EX(life)),
                            Some(SetOptions::NX),
                            false,
                        )
                        .await
                    }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(taken.is_some())
    }
}
