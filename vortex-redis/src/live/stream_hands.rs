use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::stream_hands::StreamHands;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left};

const HANDS: &str = "stream-hands";

pub struct RedisStreamHands {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisStreamHands {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisStreamHands { backbone, space }
    }

    fn hands_key(&self, room: RoomId) -> String {
        self.space.member_key(HANDS, &room.written())
    }
}

impl StreamHands for RedisStreamHands {
    fn raise(&self, room: RoomId, user: UserId, at: f64, until: f64, now: f64) -> Result<()> {
        let key = self.hands_key(room);
        let member = user.value().to_string();
        let life = seconds_left(until, now);
        self.backbone
            .execute("поднятая рука", move |pool| {
                let key = key.clone();
                let member = member.clone();
                async move {
                    let _: i64 = pool
                        .zadd(
                            key.clone(),
                            Some(SetOptions::NX),
                            None,
                            false,
                            false,
                            (at, member),
                        )
                        .await?;
                    pool.expire::<i64, _>(key, life, None).await
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn lower(&self, room: RoomId, user: UserId, _now: f64) -> Result<()> {
        let key = self.hands_key(room);
        let member = user.value().to_string();
        self.backbone
            .execute("опущенная рука", move |pool| {
                let key = key.clone();
                let member = member.clone();
                async move { pool.zrem::<i64, _, _>(key, member).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn queue(&self, room: RoomId, _now: f64) -> Result<Vec<i64>> {
        let key = self.hands_key(room);
        let standing = self
            .backbone
            .execute("очередь поднятых рук", move |pool| {
                let key = key.clone();
                async move {
                    pool.zrange::<Vec<String>, _, _, _>(key, 0, -1, None, false, None, false)
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(standing
            .iter()
            .filter_map(|member| member.parse::<i64>().ok())
            .collect())
    }

    fn clear(&self, room: RoomId, _now: f64) -> Result<()> {
        let key = self.hands_key(room);
        self.backbone
            .execute("очистка очереди рук", move |pool| {
                let key = key.clone();
                async move { pool.del::<i64, _>(key).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        let key = self.hands_key(room);
        let life = seconds_left(until, now);
        let renewed = self
            .backbone
            .execute("продление очереди рук", move |pool| {
                let key = key.clone();
                async move { pool.expire::<i64, _>(key, life, None).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(renewed == 1)
    }
}
