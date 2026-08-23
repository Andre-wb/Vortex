use std::sync::Arc;

use fred::prelude::*;
use vortex_core::room::room_id::RoomId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::recording_marks::RecordingMarks;
use vortex_live::recording::mark::Mark;
use vortex_live::recording::started::Started;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left};

const RECORDING: &str = "recording";

pub struct RedisRecordingMarks {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisRecordingMarks {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisRecordingMarks { backbone, space }
    }

    fn mark_key(&self, room: RoomId) -> String {
        self.space.member_key(RECORDING, &room.written())
    }

    fn read(&self, room: RoomId) -> Result<Option<Mark>> {
        let key = self.mark_key(room);
        let stored = self
            .backbone
            .execute("чтение отметки записи", move |pool| {
                let key = key.clone();
                async move { pool.get::<Option<String>, _>(key).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(stored.as_deref().and_then(Mark::parse))
    }
}

impl RecordingMarks for RedisRecordingMarks {
    fn start(&self, room: RoomId, mark: &Mark, now: f64) -> Result<Started> {
        let key = self.mark_key(room);
        let wire = mark.to_wire();
        let life = seconds_left(mark.until, now);
        let held = self
            .backbone
            .execute("начало записи", move |pool| {
                let key = key.clone();
                let wire = wire.clone();
                async move {
                    scripts::CLAIM
                        .run::<String>(&pool, vec![key], vec![wire.into(), life.into()])
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;

        if held == scripts::NOTHING {
            return Ok(Started::Fresh(mark.clone()));
        }
        match Mark::parse(&held).filter(|kept| kept.alive_at(now)) {
            Some(kept) => Ok(Started::Already(kept)),
            None => Ok(Started::Fresh(mark.clone())),
        }
    }

    fn stop(&self, room: RoomId, now: f64) -> Result<Option<Mark>> {
        let key = self.mark_key(room);
        let stored = self
            .backbone
            .execute("остановка записи", move |pool| {
                let key = key.clone();
                async move { pool.getdel::<Option<String>, _>(key).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(stored
            .as_deref()
            .and_then(Mark::parse)
            .filter(|kept| kept.alive_at(now)))
    }

    fn find(&self, room: RoomId, now: f64) -> Result<Option<Mark>> {
        Ok(self.read(room)?.filter(|kept| kept.alive_at(now)))
    }

    fn renew(&self, room: RoomId, until: f64, now: f64) -> Result<bool> {
        let Some(held) = self.read(room)?.filter(|kept| kept.alive_at(now)) else {
            return Ok(false);
        };
        let key = self.mark_key(room);
        let wire = held.renewed(until).to_wire();
        let life = seconds_left(until, now);
        self.backbone
            .execute("продление записи", move |pool| {
                let key = key.clone();
                let wire = wire.clone();
                async move {
                    pool.set::<(), _, _>(key, wire, Some(Expiration::EX(life)), None, false)
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(true)
    }
}
