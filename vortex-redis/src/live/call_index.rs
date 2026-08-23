use std::sync::Arc;

use fred::prelude::*;
use vortex_core::room::room_id::RoomId;
use vortex_live::call::call_id::CallId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::call_index::CallIndex;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left, CLAIM, RELEASE};

const ROOM_CALL: &str = "room-call";

pub struct RedisCallIndex {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisCallIndex {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisCallIndex { backbone, space }
    }

    fn room_key(&self, room: RoomId) -> String {
        self.space.member_key(ROOM_CALL, &room.written())
    }
}

impl CallIndex for RedisCallIndex {
    fn claim(&self, room: RoomId, call: &CallId, until: f64, now: f64) -> Result<Option<CallId>> {
        let key = self.room_key(room);
        let value = call.as_str().to_owned();
        let life = seconds_left(until, now);
        let taken = self
            .backbone
            .execute("захват звонка комнатой", move |pool| {
                let key = key.clone();
                let value = value.clone();
                async move {
                    CLAIM
                        .run::<String>(&pool, vec![key], vec![value.into(), life.into()])
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;

        if taken == scripts::NOTHING {
            return Ok(None);
        }
        Ok(CallId::parse(&taken).ok())
    }

    fn find(&self, room: RoomId, _now: f64) -> Result<Option<CallId>> {
        let key = self.room_key(room);
        let stored = self
            .backbone
            .execute(
                "чтение активного звонка комнаты",
                move |pool| {
                    let key = key.clone();
                    async move { pool.get::<Option<String>, _>(key).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(stored.and_then(|raw| CallId::parse(&raw).ok()))
    }

    fn release(&self, room: RoomId, call: &CallId, _now: f64) -> Result<bool> {
        let key = self.room_key(room);
        let value = call.as_str().to_owned();
        let released = self
            .backbone
            .execute("освобождение комнаты", move |pool| {
                let key = key.clone();
                let value = value.clone();
                async move {
                    RELEASE
                        .run::<i64>(&pool, vec![key], vec![value.into()])
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(released == 1)
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        let key = self.room_key(room);
        let life = seconds_left(until, now);
        let renewed = self
            .backbone
            .execute(
                "продление активного звонка комнаты",
                move |pool| {
                    let key = key.clone();
                    async move { pool.expire::<i64, _>(key, life, None).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(renewed == 1)
    }
}
