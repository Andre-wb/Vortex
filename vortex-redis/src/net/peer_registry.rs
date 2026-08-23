use std::sync::Arc;

use fred::prelude::*;
use vortex_net::ports::peer_registry::PeerRegistry;
use vortex_net::registry::address::PeerAddress;
use vortex_net::registry::name::PeerName;
use vortex_net::registry::peer::PeerRecord;
use vortex_net::registry::pubkey::NodePubkey;
use vortex_net::registry::refusal::{RegistryError, Result};

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::net::scripts::{self, ALIVE, FORGET_DEAD, OBSERVE};

const PEERS: &str = "peers";
const SEEN: &str = "peers-seen";
const ROOMS: &str = "peer-rooms";

pub struct RedisPeerRegistry {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisPeerRegistry {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisPeerRegistry { backbone, space }
    }

    fn peers_key(&self) -> String {
        self.space.key(PEERS)
    }

    fn seen_key(&self) -> String {
        self.space.key(SEEN)
    }

    fn rooms_key(&self) -> String {
        self.space.key(ROOMS)
    }
}

impl PeerRegistry for RedisPeerRegistry {
    fn observe(&self, record: &PeerRecord) -> Result<bool> {
        let keys = vec![self.peers_key(), self.seen_key()];
        let address = record.address().written().to_owned();
        let name = record.name().written().to_owned();
        let port = i64::from(record.port());
        let pubkey = record
            .pubkey()
            .map(|key| key.written().to_owned())
            .unwrap_or_default();
        let seen = record.last_seen();

        let fresh = self
            .backbone
            .execute("запись узла в реестр", move |pool| {
                let keys = keys.clone();
                let args: Vec<Value> = vec![
                    address.clone().into(),
                    name.clone().into(),
                    port.into(),
                    pubkey.clone().into(),
                    seen.into(),
                ];
                async move { OBSERVE.run::<i64>(&pool, keys, args).await }
            })
            .map_err(|_| RegistryError::Unavailable)?;
        Ok(fresh == 1)
    }

    fn find(&self, address: &PeerAddress) -> Result<Option<PeerRecord>> {
        let key = self.peers_key();
        let named = address.written().to_owned();
        let row = self
            .backbone
            .execute("чтение узла из реестра", move |pool| {
                let key = key.clone();
                let named = named.clone();
                async move { pool.hget::<Option<String>, _, _>(key, named).await }
            })
            .map_err(|_| RegistryError::Unavailable)?;
        Ok(row.and_then(|record| record_of(address.written(), &record)))
    }

    fn alive(&self, now: f64, timeout: f64) -> Result<Vec<PeerRecord>> {
        let keys = vec![self.peers_key(), self.seen_key()];
        let edge = now - timeout;
        let rows = self
            .backbone
            .execute("список живых узлов", move |pool| {
                let keys = keys.clone();
                let args: Vec<Value> = vec![edge.into()];
                async move { ALIVE.run::<Vec<String>>(&pool, keys, args).await }
            })
            .map_err(|_| RegistryError::Unavailable)?;

        Ok(rows
            .chunks_exact(2)
            .filter_map(|row| record_of(&row[0], &row[1]))
            .collect())
    }

    fn forget_dead(&self, now: f64, timeout: f64) -> Result<usize> {
        let keys = vec![self.peers_key(), self.seen_key(), self.rooms_key()];
        let edge = now - timeout;
        let dropped = self
            .backbone
            .execute("уборка мёртвых узлов", move |pool| {
                let keys = keys.clone();
                let args: Vec<Value> = vec![edge.into()];
                async move { FORGET_DEAD.run::<i64>(&pool, keys, args).await }
            })
            .map_err(|_| RegistryError::Unavailable)?;
        Ok(dropped.max(0) as usize)
    }

    fn set_rooms(&self, address: &PeerAddress, document: &str) -> Result<()> {
        let key = self.rooms_key();
        let named = address.written().to_owned();
        let text = document.to_owned();
        self.backbone
            .execute("запись комнат узла", move |pool| {
                let key = key.clone();
                let named = named.clone();
                let text = text.clone();
                async move { pool.hset::<i64, _, _>(key, (named, text)).await }
            })
            .map_err(|_| RegistryError::Unavailable)?;
        Ok(())
    }

    fn rooms(&self, address: &PeerAddress) -> Result<Option<String>> {
        let key = self.rooms_key();
        let named = address.written().to_owned();
        self.backbone
            .execute("чтение комнат узла", move |pool| {
                let key = key.clone();
                let named = named.clone();
                async move { pool.hget::<Option<String>, _, _>(key, named).await }
            })
            .map_err(|_| RegistryError::Unavailable)
    }

    fn count(&self) -> Result<usize> {
        let key = self.seen_key();
        let total = self
            .backbone
            .execute("счёт узлов реестра", move |pool| {
                let key = key.clone();
                async move { pool.zcard::<i64, _>(key).await }
            })
            .map_err(|_| RegistryError::Unavailable)?;
        Ok(total.max(0) as usize)
    }
}

fn record_of(address: &str, row: &str) -> Option<PeerRecord> {
    let named = PeerAddress::parse(address).ok()?;
    let (port, seen, pubkey, name) = scripts::read(row)?;
    let called = PeerName::parse(&name).ok()?;
    let key = pubkey.as_deref().and_then(NodePubkey::parse);
    Some(PeerRecord::seen(named, called, port, key, seen))
}
