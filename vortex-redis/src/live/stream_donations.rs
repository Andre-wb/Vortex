use std::sync::Arc;

use fred::prelude::*;
use vortex_core::room::room_id::RoomId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::stream_donations::StreamDonations;
use vortex_live::stream::donation::Donation;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left};

const DONATIONS: &str = "stream-donations";

pub struct RedisStreamDonations {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisStreamDonations {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisStreamDonations { backbone, space }
    }

    fn log_key(&self, room: RoomId) -> String {
        self.space.member_key(DONATIONS, &room.written())
    }
}

impl StreamDonations for RedisStreamDonations {
    fn add(&self, room: RoomId, donation: &Donation, until: f64, now: f64) -> Result<()> {
        let key = self.log_key(room);
        let wire = donation.to_wire();
        let life = seconds_left(until, now);
        self.backbone
            .execute("донат трансляции", move |pool| {
                let key = key.clone();
                let wire = wire.clone();
                async move {
                    let _: i64 = pool.rpush(key.clone(), wire).await?;
                    pool.expire::<i64, _>(key, life, None).await
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn list(&self, room: RoomId, _now: f64) -> Result<Vec<Donation>> {
        let key = self.log_key(room);
        let kept = self
            .backbone
            .execute(
                "чтение донатов трансляции",
                move |pool| {
                    let key = key.clone();
                    async move { pool.lrange::<Vec<String>, _>(key, 0, -1).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(kept.iter().filter_map(|raw| Donation::parse(raw)).collect())
    }

    fn clear(&self, room: RoomId, _now: f64) -> Result<()> {
        let key = self.log_key(room);
        self.backbone
            .execute(
                "очистка донатов трансляции",
                move |pool| {
                    let key = key.clone();
                    async move { pool.del::<i64, _>(key).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        let key = self.log_key(room);
        let life = seconds_left(until, now);
        let renewed = self
            .backbone
            .execute(
                "продление донатов трансляции",
                move |pool| {
                    let key = key.clone();
                    async move { pool.expire::<i64, _>(key, life, None).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(renewed == 1)
    }
}
