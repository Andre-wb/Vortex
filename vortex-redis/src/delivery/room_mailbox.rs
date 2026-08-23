use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;
use vortex_delivery::error::{Result, StateError};
use vortex_delivery::mailbox::entry::Entry;
use vortex_delivery::mailbox::limits;
use vortex_delivery::message::payload::Payload;
use vortex_delivery::ports::room_mailbox::RoomMailbox;

use crate::backbone::RedisBackbone;
use crate::delivery::scripts::{self, COLLECT, DEPOSIT, TRIM_STALE};
use crate::keys::KeySpace;

const QUEUE: &str = "room-queue";
const INDEX: &str = "room-index";
const SEQUENCE: &str = "room-sequence";

pub struct RedisRoomMailbox {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
    depth: usize,
    lifetime: f64,
}

impl RedisRoomMailbox {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        Self::sized(backbone, limits::ROOM_DEPTH, limits::ROOM_LIFETIME_SECONDS)
    }

    pub fn sized(backbone: Arc<RedisBackbone>, depth: usize, lifetime: f64) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisRoomMailbox {
            backbone,
            space,
            depth,
            lifetime,
        }
    }

    fn index_key(&self) -> String {
        self.space.key(INDEX)
    }

    fn sequence_key(&self) -> String {
        self.space.key(SEQUENCE)
    }

    fn queue_key(&self, member: &str) -> String {
        self.space.member_key(QUEUE, member)
    }
}

fn member_of(room: RoomId, reader: UserId) -> String {
    format!("{}-{}", room.value(), reader.value())
}

impl RoomMailbox for RedisRoomMailbox {
    fn deposit(&self, room: RoomId, readers: &[UserId], payload: &Payload, now: f64) -> Result<()> {
        if readers.is_empty() {
            return Ok(());
        }
        let members: Vec<String> = readers.iter().map(|r| member_of(room, *r)).collect();
        let mut keys = vec![self.sequence_key(), self.index_key()];
        keys.extend(members.iter().map(|m| self.queue_key(m)));

        let text = payload.written().to_owned();
        let depth = self.depth as i64;
        let lifetime = self.lifetime;

        self.backbone
            .execute(
                "постановка в очередь комнаты",
                move |pool| {
                    let keys = keys.clone();
                    let mut args: Vec<Value> = vec![
                        now.into(),
                        lifetime.into(),
                        depth.into(),
                        text.clone().into(),
                    ];
                    args.extend(members.iter().map(|m| Value::from(m.clone())));
                    async move { DEPOSIT.run::<i64>(&pool, keys, args).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn collect(&self, room: RoomId, reader: UserId) -> Result<Vec<Entry>> {
        let member = member_of(room, reader);
        let keys = vec![self.queue_key(&member), self.index_key()];

        let rows = self
            .backbone
            .execute("выборка очереди комнаты", move |pool| {
                let keys = keys.clone();
                let args: Vec<Value> = vec![member.clone().into()];
                async move { COLLECT.run::<Vec<String>>(&pool, keys, args).await }
            })
            .map_err(|_| StateError::Unavailable)?;

        Ok(entries_of(rows))
    }

    fn sweep(&self, now: f64) -> Result<usize> {
        let index = self.index_key();
        let members = self
            .backbone
            .execute("список очередей комнат", move |pool| {
                let index = index.clone();
                async move { pool.smembers::<Vec<String>, _>(index).await }
            })
            .map_err(|_| StateError::Unavailable)?;

        let mut removed = 0usize;
        for member in members {
            let keys = vec![self.queue_key(&member), self.index_key()];
            let lifetime = self.lifetime;
            let dropped = self
                .backbone
                .execute("уборка очереди комнаты", move |pool| {
                    let keys = keys.clone();
                    let args: Vec<Value> = vec![now.into(), lifetime.into(), member.clone().into()];
                    async move { TRIM_STALE.run::<i64>(&pool, keys, args).await }
                })
                .map_err(|_| StateError::Unavailable)?;
            removed += dropped.max(0) as usize;
        }
        Ok(removed)
    }

    fn tally(&self) -> Result<(usize, usize)> {
        let index = self.index_key();
        let members = self
            .backbone
            .execute("список очередей комнат", move |pool| {
                let index = index.clone();
                async move { pool.smembers::<Vec<String>, _>(index).await }
            })
            .map_err(|_| StateError::Unavailable)?;

        let mut queues = 0usize;
        let mut total = 0usize;
        for member in &members {
            let key = self.queue_key(member);
            let depth = self
                .backbone
                .execute("длина очереди комнаты", move |pool| {
                    let key = key.clone();
                    async move { pool.llen::<u64, _>(key).await }
                })
                .map_err(|_| StateError::Unavailable)?;
            if depth > 0 {
                queues += 1;
                total += depth as usize;
            }
        }
        Ok((queues, total))
    }
}

pub fn entries_of(rows: Vec<String>) -> Vec<Entry> {
    rows.into_iter()
        .filter_map(|row| {
            let stamp = scripts::stamp_of(&row)?;
            let payload = scripts::payload_of(&row)?;
            Some(Entry::new(stamp, Payload::of(payload)))
        })
        .collect()
}
