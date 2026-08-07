use std::sync::Arc;

use fred::prelude::*;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::keys::KeySpace;

use crate::blocking::memory_store::InMemoryBlockStore;
use crate::domain::block_record::BlockRecord;
use crate::domain::client_ip::ClientIp;
use crate::domain::timestamp::Timestamp;
use crate::ports::block_store::BlockStore;
use crate::ports::clock::Clock;
use crate::ports::prunable::Prunable;
use crate::redis::record_codec;

const DOMAIN: &str = "waf";
const BLOCK_NAME: &str = "block";
const INDEX_NAME: &str = "block-index";
const TTL_MARGIN_SECS: u64 = 60;

pub struct RedisBlockStore {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<InMemoryBlockStore>,
    clock: Arc<dyn Clock>,
    space: KeySpace,
}

impl RedisBlockStore {
    pub fn new(backbone: Arc<RedisBackbone>, clock: Arc<dyn Clock>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisBlockStore {
            backbone,
            fallback: Arc::new(InMemoryBlockStore::new(clock.clone())),
            clock,
            space,
        }
    }

    pub fn fallback(&self) -> &Arc<InMemoryBlockStore> {
        &self.fallback
    }

    fn block_key(&self, ip: &ClientIp) -> String {
        self.space.member_key(BLOCK_NAME, &ip.to_string())
    }

    fn index_key(&self) -> String {
        self.space.key(INDEX_NAME)
    }

    fn forget(&self, ip: &ClientIp) {
        let key = self.block_key(ip);
        let index = self.index_key();
        let address = ip.to_string();
        let _ = self.backbone.execute("снятие блокировки", move |pool| {
            let key = key.clone();
            let index = index.clone();
            let address = address.clone();
            async move {
                let _: i64 = pool.del(key).await?;
                let _: i64 = pool.srem(index, address).await?;
                Ok::<(), Error>(())
            }
        });
    }

    fn read(&self, ip: &ClientIp) -> Option<BlockRecord> {
        let key = self.block_key(ip);
        let stored = self.backbone.execute("чтение блокировки", move |pool| {
            let key = key.clone();
            async move { pool.get::<Option<String>, _>(key).await }
        });

        match stored {
            Ok(Some(payload)) => record_codec::decode(&payload),
            Ok(None) => None,
            Err(_) => self
                .fallback
                .list()
                .into_iter()
                .find_map(
                    |(known, record)| {
                        if &known == ip {
                            Some(record)
                        } else {
                            None
                        }
                    },
                ),
        }
    }

    fn addresses(&self) -> Vec<ClientIp> {
        let index = self.index_key();
        let listed = self.backbone.execute("список блокировок", move |pool| {
            let index = index.clone();
            async move { pool.smembers::<Vec<String>, _>(index).await }
        });
        listed
            .unwrap_or_default()
            .into_iter()
            .map(ClientIp::new)
            .collect()
    }
}

impl BlockStore for RedisBlockStore {
    fn put(&self, ip: &ClientIp, record: BlockRecord) {
        let key = self.block_key(ip);
        let index = self.index_key();
        let address = ip.to_string();
        let payload = record_codec::encode(&record);
        let ttl = record.duration_secs.saturating_add(TTL_MARGIN_SECS).max(1);

        let stored = self.backbone.execute("запись блокировки", move |pool| {
            let key = key.clone();
            let index = index.clone();
            let address = address.clone();
            let payload = payload.clone();
            async move {
                let _: () = pool
                    .set(key, payload, Some(Expiration::EX(ttl as i64)), None, false)
                    .await?;
                let _: i64 = pool.sadd(index, address).await?;
                Ok::<(), Error>(())
            }
        });

        if stored.is_err() {
            self.fallback.put(ip, record);
        }
    }

    fn is_blocked(&self, ip: &ClientIp, now: Timestamp) -> bool {
        match self.read(ip) {
            Some(record) if record.is_active_at(now) => true,
            Some(_) => {
                self.forget(ip);
                self.fallback.remove(ip);
                false
            }
            None => self.fallback.is_blocked(ip, now),
        }
    }

    fn remove(&self, ip: &ClientIp) -> bool {
        let existed = self.read(ip).is_some();
        self.forget(ip);
        let locally = self.fallback.remove(ip);
        existed || locally
    }

    fn list(&self) -> Vec<(ClientIp, BlockRecord)> {
        let mut listed: Vec<(ClientIp, BlockRecord)> = Vec::new();
        for ip in self.addresses() {
            match self.read(&ip) {
                Some(record) => listed.push((ip, record)),
                None => self.forget(&ip),
            }
        }
        for (ip, record) in self.fallback.list() {
            if !listed.iter().any(|(known, _)| known == &ip) {
                listed.push((ip, record));
            }
        }
        listed.sort_by(|left, right| left.0.cmp(&right.0));
        listed
    }

    fn len(&self) -> usize {
        self.list().len()
    }
}

impl Prunable for RedisBlockStore {
    fn name(&self) -> &'static str {
        "redis-block-store"
    }

    fn prune(&self) -> usize {
        let now = self.clock.now();
        let mut removed = self.fallback.prune();
        for ip in self.addresses() {
            match self.read(&ip) {
                Some(record) if record.is_active_at(now) => {}
                Some(_) => {
                    self.forget(&ip);
                    removed += 1;
                }
                None => self.forget(&ip),
            }
        }
        removed
    }
}
