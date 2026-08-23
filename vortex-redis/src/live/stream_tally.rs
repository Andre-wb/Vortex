use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use fred::prelude::*;
use vortex_core::room::room_id::RoomId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::stream_tally::StreamTally;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left, RAISE};

const REACTIONS: &str = "stream-reactions";
const PEAKS: &str = "stream-peaks";
const PEAK_FIELD: &str = "peak";

pub struct RedisStreamTally {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisStreamTally {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisStreamTally { backbone, space }
    }

    fn reactions_key(&self, room: RoomId) -> String {
        self.space.member_key(REACTIONS, &room.written())
    }

    fn peak_key(&self, room: RoomId) -> String {
        self.space.member_key(PEAKS, &room.written())
    }
}

impl StreamTally for RedisStreamTally {
    fn count_reaction(&self, room: RoomId, emoji: &str, until: f64, now: f64) -> Result<()> {
        let key = self.reactions_key(room);
        let field = emoji.to_owned();
        let life = seconds_left(until, now);
        self.backbone
            .execute("счёт реакции трансляции", move |pool| {
                let key = key.clone();
                let field = field.clone();
                async move {
                    let _: i64 = pool.hincrby(key.clone(), field, 1).await?;
                    pool.expire::<i64, _>(key, life, None).await
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn reactions(&self, room: RoomId, _now: f64) -> Result<BTreeMap<String, u64>> {
        let key = self.reactions_key(room);
        let counted = self
            .backbone
            .execute(
                "чтение реакций трансляции",
                move |pool| {
                    let key = key.clone();
                    async move { pool.hgetall::<HashMap<String, String>, _>(key).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        Ok(counted
            .into_iter()
            .filter_map(|(emoji, count)| count.parse::<u64>().ok().map(|count| (emoji, count)))
            .collect())
    }

    fn raise_peak(&self, room: RoomId, seen: u64, until: f64, now: f64) -> Result<u64> {
        let key = self.peak_key(room);
        let life = seconds_left(until, now);
        let peak = self
            .backbone
            .execute("подъём пика зрителей", move |pool| {
                let key = key.clone();
                async move {
                    RAISE
                        .run::<i64>(
                            &pool,
                            vec![key],
                            vec![PEAK_FIELD.into(), (seen as i64).into(), life.into()],
                        )
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(peak.max(0) as u64)
    }

    fn peak(&self, room: RoomId, _now: f64) -> Result<u64> {
        let key = self.peak_key(room);
        let stored = self
            .backbone
            .execute("чтение пика зрителей", move |pool| {
                let key = key.clone();
                async move { pool.hget::<Option<String>, _, _>(key, PEAK_FIELD).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(stored
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or_default())
    }

    fn clear(&self, room: RoomId, _now: f64) -> Result<()> {
        let reactions = self.reactions_key(room);
        let peak = self.peak_key(room);
        self.backbone
            .execute(
                "очистка счётчиков трансляции",
                move |pool| {
                    let reactions = reactions.clone();
                    let peak = peak.clone();
                    async move { pool.del::<i64, _>(vec![reactions, peak]).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        let reactions = self.reactions_key(room);
        let peak = self.peak_key(room);
        let life = seconds_left(until, now);
        let renewed = self
            .backbone
            .execute(
                "продление счётчиков трансляции",
                move |pool| {
                    let reactions = reactions.clone();
                    let peak = peak.clone();
                    async move {
                        let _: i64 = pool.expire(reactions, life, None).await?;
                        pool.expire::<i64, _>(peak, life, None).await
                    }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(renewed == 1)
    }
}
