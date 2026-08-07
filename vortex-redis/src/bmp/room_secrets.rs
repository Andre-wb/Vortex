use std::sync::Arc;

use fred::prelude::*;
use vortex_bmp::ports::room_secrets::RoomSecrets;
use vortex_bmp::secret::value::BmpSecret;
use vortex_bmp::secrets::memory_secrets::MemoryRoomSecrets;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;

const DOMAIN: &str = "bmp";
const SECRET_NAME: &str = "secret";

pub struct RedisRoomSecrets {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<MemoryRoomSecrets>,
    space: KeySpace,
}

impl RedisRoomSecrets {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisRoomSecrets {
            backbone,
            fallback: Arc::new(MemoryRoomSecrets::new()),
            space,
        }
    }

    pub fn fallback(&self) -> &Arc<MemoryRoomSecrets> {
        &self.fallback
    }

    fn secret_key(&self, room_id: i64) -> String {
        self.space.member_key(SECRET_NAME, &room_id.to_string())
    }
}

impl RoomSecrets for RedisRoomSecrets {
    fn set(&self, room_id: i64, secret: BmpSecret) {
        let key = self.secret_key(room_id);
        let index = self.space.key("secret-index");
        let hex = secret.to_hex();

        let stored =
            self.backbone
                .execute("запись секрета комнаты", move |pool| {
                    let key = key.clone();
                    let index = index.clone();
                    let hex = hex.clone();
                    async move {
                        let _: () = pool.set(key, hex, None, None, false).await?;
                        let _: () = pool.sadd(index, room_id).await?;
                        Ok::<(), Error>(())
                    }
                });

        if stored.is_err() {
            self.fallback.set(room_id, secret);
        }
    }

    fn get(&self, room_id: i64) -> Option<BmpSecret> {
        let key = self.secret_key(room_id);
        let stored =
            self.backbone
                .execute("чтение секрета комнаты", move |pool| {
                    let key = key.clone();
                    async move { pool.get::<Option<String>, _>(key).await }
                });

        match stored {
            Ok(Some(hex)) => match BmpSecret::parse(&hex) {
                Ok(secret) => Some(secret),
                Err(error) => {
                    log::warn!("BMP: секрет комнаты {room_id} в Redis повреждён — {error}");
                    None
                }
            },
            Ok(None) | Err(_) => self.fallback.get(room_id),
        }
    }

    fn remove(&self, room_id: i64) {
        let key = self.secret_key(room_id);
        let index = self.space.key("secret-index");
        let _ = self.backbone.execute(
            "удаление секрета комнаты",
            move |pool| {
                let key = key.clone();
                let index = index.clone();
                async move {
                    let _: () = pool.del(key).await?;
                    let _: () = pool.srem(index, room_id).await?;
                    Ok::<(), Error>(())
                }
            },
        );
        self.fallback.remove(room_id);
    }

    fn len(&self) -> usize {
        let index = self.space.key("secret-index");
        let counted =
            self.backbone.execute("число секретов комнат", move |pool| {
                let index = index.clone();
                async move { pool.scard::<u64, _>(index).await }
            });
        counted.unwrap_or_default() as usize + self.fallback.len()
    }
}
