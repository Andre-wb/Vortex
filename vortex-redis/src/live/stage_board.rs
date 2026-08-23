use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::stage_board::StageBoard;
use vortex_live::stage::record::Stage;
use vortex_live::store::swapped::ATTEMPTS;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left, SWAP_KEEPING_LIFE};

const STAGE: &str = "stage";

pub struct RedisStageBoard {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisStageBoard {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisStageBoard { backbone, space }
    }

    fn stage_key(&self, room: RoomId) -> String {
        self.space.member_key(STAGE, &room.written())
    }

    fn read(&self, room: RoomId) -> Result<Option<(String, Stage)>> {
        let key = self.stage_key(room);
        let stored = self
            .backbone
            .execute("чтение сцены", move |pool| {
                let key = key.clone();
                async move { pool.get::<Option<String>, _>(key).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(stored.and_then(|raw| Stage::parse(&raw).map(|stage| (raw, stage))))
    }

    fn rewrite(
        &self,
        room: RoomId,
        now: f64,
        change: impl Fn(&Stage) -> Stage,
    ) -> Result<Option<Stage>> {
        for _ in 0..ATTEMPTS {
            let Some((raw, held)) = self.read(room)? else {
                return Ok(None);
            };
            if !held.alive_at(now) {
                return Ok(None);
            }
            let replacement = change(&held);
            let key = self.stage_key(room);
            let wire = replacement.to_wire();
            let life = seconds_left(replacement.until, now);
            let outcome = self
                .backbone
                .execute("замена сцены", move |pool| {
                    let key = key.clone();
                    let raw = raw.clone();
                    let wire = wire.clone();
                    async move {
                        SWAP_KEEPING_LIFE
                            .run::<i64>(
                                &pool,
                                vec![key],
                                vec![raw.into(), wire.into(), life.into()],
                            )
                            .await
                    }
                })
                .map_err(|_| StateError::Unavailable)?;

            match outcome {
                scripts::SWAPPED => return Ok(Some(replacement)),
                scripts::ABSENT => return Ok(None),
                _ => continue,
            }
        }
        Err(StateError::Unavailable)
    }
}

impl StageBoard for RedisStageBoard {
    fn open(&self, room: RoomId, stage: &Stage, now: f64) -> Result<()> {
        let key = self.stage_key(room);
        let wire = stage.to_wire();
        let life = seconds_left(stage.until, now);
        self.backbone
            .execute("открытие сцены", move |pool| {
                let key = key.clone();
                let wire = wire.clone();
                async move {
                    pool.set::<(), _, _>(key, wire, Some(Expiration::EX(life)), None, false)
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)
    }

    fn close(&self, room: RoomId, now: f64) -> Result<bool> {
        let held = self.read(room)?.filter(|(_, stage)| stage.alive_at(now));
        let key = self.stage_key(room);
        let dropped = self
            .backbone
            .execute("закрытие сцены", move |pool| {
                let key = key.clone();
                async move { pool.del::<i64, _>(key).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(dropped > 0 && held.is_some())
    }

    fn find(&self, room: RoomId, now: f64) -> Result<Option<Stage>> {
        Ok(self
            .read(room)?
            .map(|(_, stage)| stage)
            .filter(|stage| stage.alive_at(now)))
    }

    fn add(&self, room: RoomId, speaker: UserId, until: f64, now: f64) -> Result<Option<Stage>> {
        self.rewrite(room, now, |held| held.with(speaker.value(), until))
    }

    fn remove(&self, room: RoomId, speaker: UserId, until: f64, now: f64) -> Result<Option<Stage>> {
        self.rewrite(room, now, |held| held.without(speaker.value(), until))
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        Ok(self
            .rewrite(room, now, |held| held.renewed(until))?
            .is_some())
    }
}
