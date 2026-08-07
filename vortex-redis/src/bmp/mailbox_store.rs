use std::sync::Arc;

use fred::prelude::*;
use vortex_bmp::config::storage::StorageConfig;
use vortex_bmp::mailbox::bucket::bucket;
use vortex_bmp::mailbox::fetched::FetchedMessage;
use vortex_bmp::mailbox::id::MailboxId;
use vortex_bmp::ports::clock::Clock;
use vortex_bmp::ports::mailbox_store::MailboxStore;
use vortex_bmp::store::memory_store::MemoryMailboxStore;
use vortex_bmp::store::refusal::DepositRefusal;
use vortex_bmp::store::stats::StoreStats;

use crate::backbone::RedisBackbone;
use crate::bmp::scripts;
use crate::keys::KeySpace;

const DOMAIN: &str = "bmp";
const BOX_NAME: &str = "box";
const COLLECT_CHUNK: usize = 200;
const BOX_TTL_MARGIN_SECS: f64 = 3600.0;

pub struct RedisMailboxStore {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<MemoryMailboxStore>,
    clock: Arc<dyn Clock>,
    config: StorageConfig,
    space: KeySpace,
}

impl RedisMailboxStore {
    pub fn new(backbone: Arc<RedisBackbone>, clock: Arc<dyn Clock>, config: StorageConfig) -> Self {
        let space = backbone.key_space(DOMAIN);
        let fallback = Arc::new(MemoryMailboxStore::new(clock.clone(), config));
        RedisMailboxStore {
            backbone,
            fallback,
            clock,
            config,
            space,
        }
    }

    pub fn fallback(&self) -> &Arc<MemoryMailboxStore> {
        &self.fallback
    }

    fn box_key(&self, mailbox: &MailboxId) -> String {
        self.space.member_key(BOX_NAME, mailbox.as_str())
    }

    fn script_keys(&self, mailbox: &MailboxId) -> Vec<String> {
        vec![
            self.box_key(mailbox),
            self.space.key("index"),
            self.space.key("bytes"),
            self.space.key("total-bytes"),
            self.space.key("sequence"),
            self.space.key("stats"),
        ]
    }

    fn lower_bound(&self, since: f64, now: f64) -> f64 {
        let horizon = now - self.config.ttl_secs;
        if since > horizon {
            since
        } else {
            horizon
        }
    }

    fn decode(&self, member: String, score: f64) -> Option<FetchedMessage> {
        let (_, ciphertext) = member.split_once(':')?;
        Some(FetchedMessage::new(
            ciphertext.to_string(),
            bucket(score, self.config.bucket_secs),
        ))
    }

    fn fallback_holds_messages(&self) -> bool {
        self.fallback.stats().total_messages > 0
    }
}

impl MailboxStore for RedisMailboxStore {
    fn deposit(&self, mailbox: &MailboxId, ciphertext: &str) -> Result<(), DepositRefusal> {
        let now = self.clock.unix_seconds();
        let keys = self.script_keys(mailbox);
        let args: Vec<Value> = vec![
            mailbox.as_str().into(),
            ciphertext.into(),
            now.to_string().into(),
            (self.config.max_messages_per_mailbox as i64).into(),
            (self.config.max_mailboxes as i64).into(),
            (self.config.max_stored_bytes as i64).into(),
            (self.config.max_ciphertext_chars() as i64).into(),
            ((self.config.ttl_secs + BOX_TTL_MARGIN_SECS) as i64).into(),
        ];

        let outcome = self.backbone.execute("депозит в ящик", move |pool| {
            let keys = keys.clone();
            let args = args.clone();
            async move { scripts::DEPOSIT.run::<Vec<Value>>(&pool, keys, args).await }
        });

        match outcome {
            Ok(reply) => {
                let accepted = reply
                    .first()
                    .and_then(|value| value.as_i64())
                    .unwrap_or_default();
                if accepted == 1 {
                    return Ok(());
                }
                let reason = reply
                    .get(1)
                    .and_then(|value| value.as_string())
                    .unwrap_or_default();
                if reason == "too_large" {
                    Err(DepositRefusal::TooLarge)
                } else {
                    Err(DepositRefusal::AtCapacity)
                }
            }
            Err(_) => self.fallback.deposit(mailbox, ciphertext),
        }
    }

    fn fetch(&self, mailbox: &MailboxId, since: f64) -> Vec<FetchedMessage> {
        let now = self.clock.unix_seconds();
        let lower = self.lower_bound(since, now);
        let key = self.box_key(mailbox);
        let stats_key = self.space.key("stats");

        let outcome = self.backbone.execute("чтение ящика", move |pool| {
            let key = key.clone();
            let stats_key = stats_key.clone();
            async move {
                let members: Vec<(String, f64)> = pool
                    .zrangebyscore(key, format!("({lower}"), "+inf", true, None)
                    .await?;
                let _: i64 = pool.hincrby(stats_key, "fetched", 1).await?;
                Ok::<Vec<(String, f64)>, Error>(members)
            }
        });

        let mut messages = match outcome {
            Ok(members) => members
                .into_iter()
                .filter_map(|(member, score)| self.decode(member, score))
                .collect(),
            Err(_) => Vec::new(),
        };

        if self.backbone.is_degraded() || self.fallback_holds_messages() {
            messages.extend(self.fallback.fetch(mailbox, since));
        }
        messages
    }

    fn fetch_batch(
        &self,
        mailboxes: &[MailboxId],
        since: f64,
    ) -> Vec<(MailboxId, Vec<FetchedMessage>)> {
        let now = self.clock.unix_seconds();
        let lower = self.lower_bound(since, now);
        let keys: Vec<String> = mailboxes.iter().map(|id| self.box_key(id)).collect();
        let stats_key = self.space.key("stats");

        let outcome = self.backbone.execute("чтение пачки ящиков", move |pool| {
            let keys = keys.clone();
            let stats_key = stats_key.clone();
            async move {
                let pipeline = pool.next().pipeline();
                for key in &keys {
                    let _: () = pipeline
                        .zrangebyscore(key.as_str(), format!("({lower}"), "+inf", true, None)
                        .await?;
                }
                let _: () = pipeline.hincrby(stats_key, "fetched", 1).await?;
                let mut replies: Vec<Value> = pipeline.all().await?;
                replies.pop();
                let decoded: Vec<Vec<(String, f64)>> = replies
                    .into_iter()
                    .map(|reply| reply.convert().unwrap_or_default())
                    .collect();
                Ok::<Vec<Vec<(String, f64)>>, Error>(decoded)
            }
        });

        let mut found: Vec<(MailboxId, Vec<FetchedMessage>)> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        if let Ok(replies) = outcome {
            for (mailbox, members) in mailboxes.iter().zip(replies) {
                if !seen.insert(mailbox.clone()) {
                    continue;
                }
                let messages: Vec<FetchedMessage> = members
                    .into_iter()
                    .filter_map(|(member, score)| self.decode(member, score))
                    .collect();
                if !messages.is_empty() {
                    found.push((mailbox.clone(), messages));
                }
            }
        }

        if self.backbone.is_degraded() || self.fallback_holds_messages() {
            for (mailbox, messages) in self.fallback.fetch_batch(mailboxes, since) {
                match found.iter_mut().find(|(known, _)| known == &mailbox) {
                    Some((_, known)) => known.extend(messages),
                    None => found.push((mailbox, messages)),
                }
            }
        }
        found
    }

    fn collect_garbage(&self) -> u64 {
        let removed_locally = self.fallback.collect_garbage();
        let now = self.clock.unix_seconds();
        let cutoff = now - self.config.ttl_secs;
        let lease_key = self.space.key("gc-lease");
        let index_key = self.space.key("index");
        let keys = vec![
            String::new(),
            index_key.clone(),
            self.space.key("bytes"),
            self.space.key("total-bytes"),
            self.space.key(BOX_NAME),
            self.space.key("stats"),
        ];

        let outcome = self.backbone.execute("уборка ящиков", move |pool| {
            let lease_key = lease_key.clone();
            let index_key = index_key.clone();
            let keys = keys.clone();
            async move {
                let taken: bool = pool
                    .set(
                        lease_key,
                        "1",
                        Some(Expiration::EX(60)),
                        Some(SetOptions::NX),
                        false,
                    )
                    .await?;
                if !taken {
                    return Ok::<u64, Error>(0);
                }

                let mailboxes: Vec<String> = pool.smembers(index_key).await?;
                let mut removed = 0u64;
                for chunk in mailboxes.chunks(COLLECT_CHUNK) {
                    let mut args: Vec<Value> = vec![cutoff.to_string().into()];
                    args.extend(chunk.iter().map(|id| Value::from(id.as_str())));
                    let removed_here: u64 = scripts::COLLECT.run(&pool, keys.clone(), args).await?;
                    removed += removed_here;
                }
                Ok::<u64, Error>(removed)
            }
        });

        removed_locally + outcome.unwrap_or_default()
    }

    fn stats(&self) -> StoreStats {
        let index_key = self.space.key("index");
        let total_key = self.space.key("total-bytes");
        let stats_key = self.space.key("stats");

        let outcome = self.backbone.execute("статистика ящиков", move |pool| {
            let index_key = index_key.clone();
            let total_key = total_key.clone();
            let stats_key = stats_key.clone();
            async move {
                let mailboxes: u64 = pool.scard(index_key).await?;
                let stored: Option<u64> = pool.get(total_key).await?;
                let counters: std::collections::HashMap<String, i64> =
                    pool.hgetall(stats_key).await?;
                Ok::<(u64, u64, std::collections::HashMap<String, i64>), Error>((
                    mailboxes,
                    stored.unwrap_or_default(),
                    counters,
                ))
            }
        });

        let local = self.fallback.stats();
        match outcome {
            Ok((mailboxes, stored, counters)) => {
                let read =
                    |name: &str| counters.get(name).copied().unwrap_or_default().max(0) as u64;
                StoreStats {
                    active_mailboxes: mailboxes as usize + local.active_mailboxes,
                    total_messages: read("messages") as usize + local.total_messages,
                    stored_bytes: stored as usize + local.stored_bytes,
                    total_deposited: read("deposited") + local.total_deposited,
                    total_fetched: read("fetched") + local.total_fetched,
                    total_expired: read("expired") + local.total_expired,
                    total_refused: read("refused") + local.total_refused,
                }
            }
            Err(_) => local,
        }
    }
}
