use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::voice_presence::VoicePresence;
use vortex_live::store::swapped::ATTEMPTS;
use vortex_live::voice::joined::Joined;
use vortex_live::voice::memory::ordered;
use vortex_live::voice::participant::Participant;
use vortex_live::voice::patch::MutePatch;
use vortex_live::voice::record::Presence;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left, HOLD, HSWAP};

const CHANNEL: &str = "voice";

pub struct RedisVoicePresence {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisVoicePresence {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisVoicePresence { backbone, space }
    }

    fn channel_key(&self, room: RoomId) -> String {
        self.space.member_key(CHANNEL, &room.written())
    }

    fn read(&self, room: RoomId, user: UserId) -> Result<Option<(String, Presence)>> {
        let key = self.channel_key(room);
        let field = user.value().to_string();
        let stored = self
            .backbone
            .execute(
                "чтение участника голосового канала",
                move |pool| {
                    let key = key.clone();
                    let field = field.clone();
                    async move { pool.hget::<Option<String>, _, _>(key, field).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        Ok(stored.and_then(|raw| Presence::parse(&raw).map(|record| (raw, record))))
    }

    fn swap(
        &self,
        room: RoomId,
        user: UserId,
        expected: String,
        replacement: String,
        until: f64,
        now: f64,
    ) -> Result<i64> {
        let key = self.channel_key(room);
        let field = user.value().to_string();
        let life = seconds_left(until, now);
        self.backbone
            .execute(
                "замена участника голосового канала",
                move |pool| {
                    let key = key.clone();
                    let field = field.clone();
                    let expected = expected.clone();
                    let replacement = replacement.clone();
                    async move {
                        HSWAP
                            .run::<i64>(
                                &pool,
                                vec![key],
                                vec![
                                    field.into(),
                                    expected.into(),
                                    replacement.into(),
                                    life.into(),
                                ],
                            )
                            .await
                    }
                },
            )
            .map_err(|_| StateError::Unavailable)
    }

    fn forget(&self, room: RoomId, user: UserId) -> Result<()> {
        let key = self.channel_key(room);
        let field = user.value().to_string();
        self.backbone
            .execute(
                "уборка истёкшего участника голосового канала",
                move |pool| {
                    let key = key.clone();
                    let field = field.clone();
                    async move { pool.hdel::<i64, _, _>(key, field).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn rewrite(
        &self,
        room: RoomId,
        user: UserId,
        now: f64,
        change: impl Fn(&Presence) -> Presence,
    ) -> Result<Option<Participant>> {
        for _ in 0..ATTEMPTS {
            let Some((raw, held)) = self.read(room, user)? else {
                return Ok(None);
            };
            if !held.alive_at(now) {
                return Ok(None);
            }
            let replacement = change(&held);
            if self.swap(
                room,
                user,
                raw,
                replacement.to_wire(),
                replacement.until,
                now,
            )? == scripts::SWAPPED
            {
                return Ok(Some(replacement.participant));
            }
        }
        Err(StateError::Unavailable)
    }
}

impl VoicePresence for RedisVoicePresence {
    fn join(&self, room: RoomId, presence: &Presence, now: f64) -> Result<Joined> {
        let Some(user) = UserId::of(presence.participant.user_id) else {
            return Err(StateError::Unavailable);
        };

        for _ in 0..ATTEMPTS {
            let key = self.channel_key(room);
            let field = user.value().to_string();
            let wire = presence.to_wire();
            let life = seconds_left(presence.until, now);

            let existing = self
                .backbone
                .execute("вход в голосовой канал", move |pool| {
                    let key = key.clone();
                    let field = field.clone();
                    let wire = wire.clone();
                    async move {
                        HOLD.run::<String>(
                            &pool,
                            vec![key],
                            vec![field.into(), wire.into(), life.into()],
                        )
                        .await
                    }
                })
                .map_err(|_| StateError::Unavailable)?;

            if existing == scripts::NOTHING {
                return Ok(Joined::Fresh(presence.participant.clone()));
            }
            match Presence::parse(&existing).filter(|held| held.alive_at(now)) {
                Some(held) => return Ok(Joined::Already(held.participant)),
                None => {
                    self.forget(room, user)?;
                }
            }
        }
        Err(StateError::Unavailable)
    }

    fn leave(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<Participant>> {
        let Some((_, held)) = self.read(room, user)? else {
            return Ok(None);
        };
        let key = self.channel_key(room);
        let field = user.value().to_string();
        let removed = self
            .backbone
            .execute(
                "выход из голосового канала",
                move |pool| {
                    let key = key.clone();
                    let field = field.clone();
                    async move { pool.hdel::<i64, _, _>(key, field).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        if removed == 0 || !held.alive_at(now) {
            return Ok(None);
        }
        Ok(Some(held.participant))
    }

    fn list(&self, room: RoomId, now: f64) -> Result<Vec<Participant>> {
        let key = self.channel_key(room);
        let held = self
            .backbone
            .execute(
                "список участников голосового канала",
                move |pool| {
                    let key = key.clone();
                    async move { pool.hvals::<Vec<String>, _>(key).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        Ok(ordered(
            held.iter()
                .filter_map(|raw| Presence::parse(raw))
                .filter(|record| record.alive_at(now))
                .map(|record| record.participant)
                .collect(),
        ))
    }

    fn find(&self, room: RoomId, user: UserId, now: f64) -> Result<Option<Participant>> {
        Ok(self
            .read(room, user)?
            .filter(|(_, held)| held.alive_at(now))
            .map(|(_, held)| held.participant))
    }

    fn amend(
        &self,
        room: RoomId,
        user: UserId,
        patch: MutePatch,
        until: f64,
        now: f64,
    ) -> Result<Option<Participant>> {
        self.rewrite(room, user, now, |held| held.amended(patch, until))
    }

    fn renew(&self, room: RoomId, user: UserId, until: f64, now: f64) -> Result<bool> {
        Ok(self
            .rewrite(room, user, now, |held| held.renewed(until))?
            .is_some())
    }
}
