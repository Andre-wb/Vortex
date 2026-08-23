use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_auth::challenge::secret::ChallengeSecret;
use vortex_auth::error::{Result, StateError};
use vortex_auth::ports::wallet_challenges::WalletChallenges;
use vortex_auth::token::ttl::Ttl;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;

const DOMAIN: &str = "auth";
const CHALLENGE: &str = "wallet-challenge";

pub struct RedisWalletChallenges {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisWalletChallenges {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisWalletChallenges { backbone, space }
    }

    fn challenge_key(&self, user: UserId) -> String {
        self.space.member_key(CHALLENGE, &user.value().to_string())
    }
}

impl WalletChallenges for RedisWalletChallenges {
    fn remember(&self, user: UserId, secret: &ChallengeSecret, ttl: Ttl, _now: f64) -> Result<()> {
        let key = self.challenge_key(user);
        let hex = secret.to_hex();
        let seconds = ttl.as_seconds() as i64;

        self.backbone
            .execute(
                "запись челленджа кошелька",
                move |pool| {
                    let key = key.clone();
                    let hex = hex.clone();
                    async move {
                        pool.set::<(), _, _>(key, hex, Some(Expiration::EX(seconds)), None, false)
                            .await
                    }
                },
            )
            .map_err(|_| StateError::Unavailable)
    }

    fn find(&self, user: UserId, _now: f64) -> Result<Option<ChallengeSecret>> {
        let key = self.challenge_key(user);
        let stored = self
            .backbone
            .execute("чтение челленджа кошелька", |pool| {
                let key = key.clone();
                async move { pool.get::<Option<String>, _>(key).await }
            })
            .unwrap_or(None);

        Ok(match stored {
            Some(hex) => match ChallengeSecret::parse_hex(&hex) {
                Ok(secret) => Some(secret),
                Err(error) => {
                    log::warn!(
                        "auth: челлендж кошелька учётной записи {} в Redis повреждён — {error}",
                        user.value()
                    );
                    None
                }
            },
            None => None,
        })
    }

    fn burn(&self, user: UserId) -> Result<()> {
        let key = self.challenge_key(user);
        self.backbone
            .execute(
                "сжигание челленджа кошелька",
                move |pool| {
                    let key = key.clone();
                    async move { pool.del::<i64, _>(key).await }
                },
            )
            .map(|_| ())
            .map_err(|_| StateError::Unavailable)
    }
}
