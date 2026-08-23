use std::sync::Arc;

use fred::prelude::*;
use vortex_core::room::room_id::RoomId;
use vortex_live::error::{Result, StateError};
use vortex_live::ports::stream_records::StreamRecords;
use vortex_live::store::swapped::Swapped;
use vortex_live::stream::record::Stream;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::live::scripts::{self, seconds_left, SWAP_KEEPING_LIFE};

const STREAM: &str = "stream";

pub struct RedisStreamRecords {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisStreamRecords {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisStreamRecords { backbone, space }
    }

    fn stream_key(&self, room: RoomId) -> String {
        self.space.member_key(STREAM, &room.written())
    }

    fn read(&self, room: RoomId) -> Result<Option<(String, Stream)>> {
        let key = self.stream_key(room);
        let stored = self
            .backbone
            .execute("чтение трансляции", move |pool| {
                let key = key.clone();
                async move { pool.get::<Option<String>, _>(key).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(stored.and_then(|raw| Stream::parse(&raw).map(|record| (raw, record))))
    }
}

impl StreamRecords for RedisStreamRecords {
    fn open(&self, room: RoomId, stream: &Stream, now: f64) -> Result<bool> {
        let key = self.stream_key(room);
        let wire = stream.to_wire();
        let life = seconds_left(stream.until, now);
        let taken = self
            .backbone
            .execute("запуск трансляции", move |pool| {
                let key = key.clone();
                let wire = wire.clone();
                async move {
                    pool.set::<Option<String>, _, _>(
                        key,
                        wire,
                        Some(Expiration::EX(life)),
                        Some(SetOptions::NX),
                        false,
                    )
                    .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(taken.is_some())
    }

    fn find(&self, room: RoomId, now: f64) -> Result<Option<Stream>> {
        Ok(self
            .read(room)?
            .map(|(_, record)| record)
            .filter(|record| record.alive_at(now)))
    }

    fn swap(
        &self,
        room: RoomId,
        expected: &Stream,
        replacement: &Stream,
        now: f64,
    ) -> Result<Swapped> {
        let Some((raw, held)) = self.read(room)? else {
            return Ok(Swapped::Missing);
        };
        if !held.alive_at(now) {
            return Ok(Swapped::Missing);
        }
        if &held != expected {
            return Ok(Swapped::Changed);
        }

        let key = self.stream_key(room);
        let wire = replacement.to_wire();
        let life = seconds_left(replacement.until, now);
        let outcome = self
            .backbone
            .execute("замена трансляции", move |pool| {
                let key = key.clone();
                let raw = raw.clone();
                let wire = wire.clone();
                async move {
                    SWAP_KEEPING_LIFE
                        .run::<i64>(&pool, vec![key], vec![raw.into(), wire.into(), life.into()])
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)?;

        Ok(match outcome {
            scripts::SWAPPED => Swapped::Done,
            scripts::CHANGED => Swapped::Changed,
            _ => Swapped::Missing,
        })
    }

    fn forget(&self, room: RoomId, now: f64) -> Result<Option<Stream>> {
        let key = self.stream_key(room);
        let stored = self
            .backbone
            .execute("остановка трансляции", move |pool| {
                let key = key.clone();
                async move { pool.getdel::<Option<String>, _>(key).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(stored
            .as_deref()
            .and_then(Stream::parse)
            .filter(|record| record.alive_at(now)))
    }
}
