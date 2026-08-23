use std::sync::Arc;

use fred::prelude::*;
use vortex_net::federation::virtual_room::VirtualRoomId;
use vortex_net::ports::virtual_room_ids::VirtualRoomIds;
use vortex_net::registry::refusal::{RegistryError, Result};

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::net::scripts::{self, RESERVE_BELOW};

const HANDED: &str = "virtual-room-handed";

pub struct RedisVirtualRoomIds {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisVirtualRoomIds {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisVirtualRoomIds { backbone, space }
    }

    fn handed_key(&self) -> String {
        self.space.key(HANDED)
    }
}

impl VirtualRoomIds for RedisVirtualRoomIds {
    fn next(&self) -> Result<VirtualRoomId> {
        let key = self.handed_key();
        let handed = self
            .backbone
            .execute(
                "выдача номера федеративной комнаты",
                move |pool| {
                    let key = key.clone();
                    async move { pool.decr::<i64, _>(key).await }
                },
            )
            .map_err(|_| RegistryError::Unavailable)?;
        VirtualRoomId::of(handed).ok_or(RegistryError::Unavailable)
    }

    fn reserve_below(&self, taken: VirtualRoomId) -> Result<()> {
        let keys = vec![self.handed_key()];
        let value = taken.value();
        self.backbone
            .execute(
                "резерв номера федеративной комнаты",
                move |pool| {
                    let keys = keys.clone();
                    let args: Vec<Value> = vec![value.into()];
                    async move { RESERVE_BELOW.run::<i64>(&pool, keys, args).await }
                },
            )
            .map_err(|_| RegistryError::Unavailable)?;
        Ok(())
    }
}
