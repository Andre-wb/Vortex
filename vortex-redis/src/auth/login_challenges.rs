use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::challenge::id::ChallengeId;
use vortex_auth::error::{Result, StateError};
use vortex_auth::login::record::LoginChallenge;
use vortex_auth::ports::login_challenges::LoginChallenges;
use vortex_auth::token::ttl::Ttl;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;

const DOMAIN: &str = "auth";
const CHALLENGE: &str = "login-challenge";

pub struct RedisLoginChallenges {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisLoginChallenges {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisLoginChallenges { backbone, space }
    }

    fn challenge_key(&self, id: &ChallengeId) -> String {
        self.space.member_key(CHALLENGE, id.as_str())
    }
}

impl LoginChallenges for RedisLoginChallenges {
    fn open(&self, id: &ChallengeId, record: &LoginChallenge, ttl: Ttl, _now: f64) -> Result<()> {
        let key = self.challenge_key(id);
        let wire = record.to_wire();
        let seconds = ttl.as_seconds() as i64;

        self.backbone
            .execute("запись челленджа входа", move |pool| {
                let key = key.clone();
                let wire = wire.clone();
                async move {
                    pool.set::<(), _, _>(key, wire, Some(Expiration::EX(seconds)), None, false)
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)
    }

    fn consume(&self, id: &ChallengeId, _now: f64) -> Result<Option<LoginChallenge>> {
        let key = self.challenge_key(id);
        let taken = self
            .backbone
            .execute("изъятие челленджа входа", move |pool| {
                let key = key.clone();
                async move { pool.getdel::<Option<String>, _>(key).await }
            })
            .unwrap_or(None);

        Ok(match taken {
            Some(wire) => match LoginChallenge::parse(&wire) {
                Ok(record) => Some(record),
                Err(error) => {
                    log::warn!(
                        "auth: челлендж входа {} в Redis повреждён — {error}",
                        id.as_str()
                    );
                    None
                }
            },
            None => None,
        })
    }
}
