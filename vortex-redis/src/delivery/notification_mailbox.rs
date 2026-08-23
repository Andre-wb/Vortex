use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_delivery::error::{Result, StateError};
use vortex_delivery::mailbox::entry::Entry;
use vortex_delivery::mailbox::limits;
use vortex_delivery::message::payload::Payload;
use vortex_delivery::ports::notification_mailbox::NotificationMailbox;

use crate::backbone::RedisBackbone;
use crate::delivery::room_mailbox::entries_of;
use crate::delivery::scripts::{self, COLLECT, DEPOSIT};
use crate::keys::KeySpace;

const QUEUE: &str = "note-queue";
const INDEX: &str = "note-index";
const SEQUENCE: &str = "note-sequence";

pub struct RedisNotificationMailbox {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
    depth: usize,
    lifetime: f64,
}

impl RedisNotificationMailbox {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        Self::sized(
            backbone,
            limits::NOTIFICATION_DEPTH,
            limits::NOTIFICATION_LIFETIME_SECONDS,
        )
    }

    pub fn sized(backbone: Arc<RedisBackbone>, depth: usize, lifetime: f64) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisNotificationMailbox {
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

impl NotificationMailbox for RedisNotificationMailbox {
    fn deposit(&self, reader: UserId, payload: &Payload, now: f64) -> Result<()> {
        let member = reader.value().to_string();
        let keys = vec![
            self.sequence_key(),
            self.index_key(),
            self.queue_key(&member),
        ];
        let text = payload.written().to_owned();
        let depth = self.depth as i64;
        let lifetime = self.lifetime;

        self.backbone
            .execute(
                "постановка уведомления в очередь",
                move |pool| {
                    let keys = keys.clone();
                    let args: Vec<Value> = vec![
                        now.into(),
                        lifetime.into(),
                        depth.into(),
                        text.clone().into(),
                        member.clone().into(),
                    ];
                    async move { DEPOSIT.run::<i64>(&pool, keys, args).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn collect(&self, reader: UserId) -> Result<Vec<Entry>> {
        let member = reader.value().to_string();
        let keys = vec![self.queue_key(&member), self.index_key()];

        let rows = self
            .backbone
            .execute(
                "выборка очереди уведомлений",
                move |pool| {
                    let keys = keys.clone();
                    let args: Vec<Value> = vec![member.clone().into()];
                    async move { COLLECT.run::<Vec<String>>(&pool, keys, args).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        Ok(entries_of(rows))
    }

    fn tally(&self) -> Result<(usize, usize)> {
        let index = self.index_key();
        let members = self
            .backbone
            .execute(
                "список очередей уведомлений",
                move |pool| {
                    let index = index.clone();
                    async move { pool.smembers::<Vec<String>, _>(index).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        let mut queues = 0usize;
        let mut total = 0usize;
        for member in &members {
            let key = self.queue_key(member);
            let depth = self
                .backbone
                .execute(
                    "длина очереди уведомлений",
                    move |pool| {
                        let key = key.clone();
                        async move { pool.llen::<u64, _>(key).await }
                    },
                )
                .map_err(|_| StateError::Unavailable)?;
            if depth > 0 {
                queues += 1;
                total += depth as usize;
            }
        }
        Ok((queues, total))
    }
}
