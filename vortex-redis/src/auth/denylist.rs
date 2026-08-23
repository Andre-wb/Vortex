use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::error::{Result, StateError};
use vortex_auth::ports::denylist::Denylist;
use vortex_auth::token::jti::Jti;
use vortex_auth::token::ttl::Ttl;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;

const DOMAIN: &str = "auth";
const REVOKED: &str = "revoked";

pub struct RedisDenylist {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisDenylist {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisDenylist { backbone, space }
    }

    fn revoked_key(&self, jti: &Jti) -> String {
        self.space.member_key(REVOKED, jti.as_str())
    }
}

impl Denylist for RedisDenylist {
    fn remember(&self, jti: &Jti, ttl: Ttl, _now: f64) -> Result<()> {
        let key = self.revoked_key(jti);
        let seconds = ttl.as_seconds() as i64;

        self.backbone
            .execute(
                "запись отозванного токена",
                move |pool| {
                    let key = key.clone();
                    async move {
                        pool.set::<(), _, _>(key, 1, Some(Expiration::EX(seconds)), None, false)
                            .await
                    }
                },
            )
            .map_err(|_| StateError::Unavailable)
    }

    fn holds(&self, jti: &Jti, _now: f64) -> bool {
        let key = self.revoked_key(jti);
        let answered =
            self.backbone.execute("поиск отозванного токена", |pool| {
                let key = key.clone();
                async move { pool.exists::<i64, _>(key).await }
            });
        matches!(answered, Ok(found) if found > 0)
    }
}
