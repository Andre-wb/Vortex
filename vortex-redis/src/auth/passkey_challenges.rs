use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::error::{Result, StateError};
use vortex_auth::passkey::record::PasskeyChallenge;
use vortex_auth::passkey::session::PasskeySession;
use vortex_auth::ports::passkey_challenges::PasskeyChallenges;
use vortex_auth::token::ttl::Ttl;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;

const DOMAIN: &str = "auth";
const CHALLENGE: &str = "passkey-challenge";

pub struct RedisPasskeyChallenges {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisPasskeyChallenges {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisPasskeyChallenges { backbone, space }
    }

    fn challenge_key(&self, session: &PasskeySession) -> String {
        self.space.member_key(CHALLENGE, session.as_str())
    }
}

impl PasskeyChallenges for RedisPasskeyChallenges {
    fn open(
        &self,
        session: &PasskeySession,
        record: &PasskeyChallenge,
        ttl: Ttl,
        _now: f64,
    ) -> Result<()> {
        let key = self.challenge_key(session);
        let wire = record.to_wire();
        let seconds = ttl.as_seconds() as i64;

        self.backbone
            .execute("запись челленджа passkey", move |pool| {
                let key = key.clone();
                let wire = wire.clone();
                async move {
                    pool.set::<(), _, _>(key, wire, Some(Expiration::EX(seconds)), None, false)
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)
    }

    fn consume(&self, session: &PasskeySession, _now: f64) -> Result<Option<PasskeyChallenge>> {
        let key = self.challenge_key(session);
        let taken = self
            .backbone
            .execute("изъятие челленджа passkey", move |pool| {
                let key = key.clone();
                async move { pool.getdel::<Option<String>, _>(key).await }
            })
            .unwrap_or(None);

        Ok(match taken {
            Some(wire) => match PasskeyChallenge::parse(&wire) {
                Ok(record) => Some(record),
                Err(error) => {
                    log::warn!(
                        "auth: челлендж passkey сессии {} в Redis повреждён — {error}",
                        session.as_str()
                    );
                    None
                }
            },
            None => None,
        })
    }
}
