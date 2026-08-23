use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::stream_roster::StreamRoster;
use vortex_live::store::swapped::Swapped;
use vortex_live::stream::participant::StreamParticipant;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left, HOLD, HSWAP};

const ROSTER: &str = "stream-roster";

pub struct RedisStreamRoster {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisStreamRoster {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisStreamRoster { backbone, space }
    }

    fn roster_key(&self, room: RoomId) -> String {
        self.space.member_key(ROSTER, &room.written())
    }
}

impl StreamRoster for RedisStreamRoster {
    fn seat(
        &self,
        room: RoomId,
        participant: &StreamParticipant,
        until: f64,
        now: f64,
    ) -> Result<Option<StreamParticipant>> {
        let key = self.roster_key(room);
        let field = participant.person.user_id.to_string();
        let value = participant.to_wire();
        let life = seconds_left(until, now);
        let existing = self
            .backbone
            .execute(
                "посадка зрителя трансляции",
                move |pool| {
                    let key = key.clone();
                    let field = field.clone();
                    let value = value.clone();
                    async move {
                        HOLD.run::<String>(
                            &pool,
                            vec![key],
                            vec![field.into(), value.into(), life.into()],
                        )
                        .await
                    }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        if existing == scripts::NOTHING {
            return Ok(None);
        }
        Ok(StreamParticipant::parse(&existing))
    }

    fn find(&self, room: RoomId, user: UserId, _now: f64) -> Result<Option<StreamParticipant>> {
        let key = self.roster_key(room);
        let field = user.value().to_string();
        let stored = self
            .backbone
            .execute(
                "чтение зрителя трансляции",
                move |pool| {
                    let key = key.clone();
                    let field = field.clone();
                    async move { pool.hget::<Option<String>, _, _>(key, field).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(stored.as_deref().and_then(StreamParticipant::parse))
    }

    fn list(&self, room: RoomId, _now: f64) -> Result<Vec<StreamParticipant>> {
        let key = self.roster_key(room);
        let held = self
            .backbone
            .execute(
                "список зрителей трансляции",
                move |pool| {
                    let key = key.clone();
                    async move { pool.hvals::<Vec<String>, _>(key).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        let mut seated: Vec<StreamParticipant> = held
            .iter()
            .filter_map(|raw| StreamParticipant::parse(raw))
            .collect();
        seated.sort_by_key(|left| left.person.user_id);
        Ok(seated)
    }

    fn swap_member(
        &self,
        room: RoomId,
        user: UserId,
        expected: &StreamParticipant,
        replacement: &StreamParticipant,
        until: f64,
        now: f64,
    ) -> Result<Swapped> {
        let key = self.roster_key(room);
        let field = user.value().to_string();
        let before = expected.to_wire();
        let after = replacement.to_wire();
        let life = seconds_left(until, now);
        let outcome = self
            .backbone
            .execute(
                "замена зрителя трансляции",
                move |pool| {
                    let key = key.clone();
                    let field = field.clone();
                    let before = before.clone();
                    let after = after.clone();
                    async move {
                        HSWAP
                            .run::<i64>(
                                &pool,
                                vec![key],
                                vec![field.into(), before.into(), after.into(), life.into()],
                            )
                            .await
                    }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        Ok(match outcome {
            scripts::SWAPPED => Swapped::Done,
            scripts::CHANGED => Swapped::Changed,
            _ => Swapped::Missing,
        })
    }

    fn unseat(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<StreamParticipant>> {
        let Some(held) = self.find(room, user, now)? else {
            return Ok(None);
        };
        let key = self.roster_key(room);
        let field = user.value().to_string();
        let removed = self
            .backbone
            .execute("уход зрителя трансляции", move |pool| {
                let key = key.clone();
                let field = field.clone();
                async move { pool.hdel::<i64, _, _>(key, field).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok((removed > 0).then_some(held))
    }

    fn clear(&self, room: RoomId, _now: f64) -> Result<()> {
        let key = self.roster_key(room);
        self.backbone
            .execute(
                "очистка зрителей трансляции",
                move |pool| {
                    let key = key.clone();
                    async move { pool.del::<i64, _>(key).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        let key = self.roster_key(room);
        let life = seconds_left(until, now);
        let renewed = self
            .backbone
            .execute(
                "продление зрителей трансляции",
                move |pool| {
                    let key = key.clone();
                    async move { pool.expire::<i64, _>(key, life, None).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(renewed == 1)
    }
}
