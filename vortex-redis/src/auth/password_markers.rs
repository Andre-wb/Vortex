use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_auth::error::{Result, StateError};
use vortex_auth::ports::password_markers::PasswordMarkers;
use vortex_auth::token::ttl::Ttl;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;

const DOMAIN: &str = "auth";
const MARKER: &str = "password-verified";

pub struct RedisPasswordMarkers {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisPasswordMarkers {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisPasswordMarkers { backbone, space }
    }

    fn marker_key(&self, user: UserId) -> String {
        self.space.member_key(MARKER, &user.value().to_string())
    }
}

impl PasswordMarkers for RedisPasswordMarkers {
    fn arm(&self, user: UserId, ttl: Ttl, _now: f64) -> Result<()> {
        let key = self.marker_key(user);
        let seconds = ttl.as_seconds() as i64;

        self.backbone
            .execute(
                "выдача маркера первого фактора",
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

    fn armed(&self, user: UserId, _now: f64) -> bool {
        let key = self.marker_key(user);
        let answered = self.backbone.execute(
            "поиск маркера первого фактора",
            |pool| {
                let key = key.clone();
                async move { pool.exists::<i64, _>(key).await }
            },
        );
        matches!(answered, Ok(found) if found > 0)
    }

    fn disarm(&self, user: UserId) -> Result<()> {
        let key = self.marker_key(user);
        self.backbone
            .execute(
                "сжигание маркера первого фактора",
                move |pool| {
                    let key = key.clone();
                    async move { pool.del::<i64, _>(key).await }
                },
            )
            .map(|_| ())
            .map_err(|_| StateError::Unavailable)
    }
}
