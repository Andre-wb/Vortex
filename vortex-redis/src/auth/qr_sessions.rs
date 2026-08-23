use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_auth::error::{Result, StateError};
use vortex_auth::ports::qr_sessions::QrSessions;
use vortex_auth::qr::confirmation::Confirmation;
use vortex_auth::qr::handover::Handover;
use vortex_auth::qr::record::QrSession;
use vortex_auth::qr::session_id::QrSessionId;
use vortex_auth::token::ttl::Ttl;

use crate::auth::scripts::{self, SWAP};
use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;

const DOMAIN: &str = "auth";
const SESSION: &str = "qr-session";
const DROP: &str = "";

pub struct RedisQrSessions {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
}

impl RedisQrSessions {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisQrSessions { backbone, space }
    }

    fn session_key(&self, session: &QrSessionId) -> String {
        self.space.member_key(SESSION, session.as_str())
    }

    fn read(&self, session: &QrSessionId) -> Option<(String, QrSession)> {
        let key = self.session_key(session);
        let stored = self
            .backbone
            .execute("чтение QR-сессии", move |pool| {
                let key = key.clone();
                async move { pool.get::<Option<String>, _>(key).await }
            })
            .unwrap_or(None)?;

        match QrSession::parse(&stored) {
            Ok(record) => Some((stored, record)),
            Err(error) => {
                log::warn!(
                    "auth: QR-сессия {} в Redis повреждена — {error}",
                    session.as_str()
                );
                None
            }
        }
    }

    fn swap(&self, session: &QrSessionId, expected: String, replacement: String) -> Option<i64> {
        let key = self.session_key(session);
        self.backbone
            .execute("замена QR-сессии", move |pool| {
                let key = key.clone();
                let expected = expected.clone();
                let replacement = replacement.clone();
                async move {
                    SWAP.run::<i64>(&pool, vec![key], vec![expected.into(), replacement.into()])
                        .await
                }
            })
            .ok()
    }
}

impl QrSessions for RedisQrSessions {
    fn open(&self, session: &QrSessionId, record: &QrSession, ttl: Ttl, _now: f64) -> Result<()> {
        let key = self.session_key(session);
        let wire = record.to_wire();
        let seconds = ttl.as_seconds() as i64;

        self.backbone
            .execute("запись QR-сессии", move |pool| {
                let key = key.clone();
                let wire = wire.clone();
                async move {
                    pool.set::<(), _, _>(key, wire, Some(Expiration::EX(seconds)), None, false)
                        .await
                }
            })
            .map_err(|_| StateError::Unavailable)
    }

    fn find(&self, session: &QrSessionId, _now: f64) -> Result<Option<QrSession>> {
        Ok(self.read(session).map(|(_, record)| record))
    }

    fn confirm(&self, session: &QrSessionId, user: UserId, _now: f64) -> Result<Confirmation> {
        let (stored, record) = match self.read(session) {
            Some(found) => found,
            None => return Ok(Confirmation::Missing),
        };
        if !record.state().is_pending() {
            return Ok(Confirmation::AlreadyConfirmed);
        }

        Ok(
            match self.swap(session, stored, record.confirmed_by(user).to_wire()) {
                Some(scripts::SWAPPED) => Confirmation::Confirmed,
                Some(scripts::CHANGED) => Confirmation::AlreadyConfirmed,
                Some(scripts::ABSENT) | None => Confirmation::Missing,
                Some(_) => Confirmation::Missing,
            },
        )
    }

    fn hand_over(&self, session: &QrSessionId, _now: f64) -> Result<Handover> {
        let (stored, record) = match self.read(session) {
            Some(found) => found,
            None => return Ok(Handover::Missing),
        };
        let user = match record.state().confirmed_by() {
            Some(user) => user,
            None => return Ok(Handover::Pending),
        };

        Ok(match self.swap(session, stored, DROP.to_owned()) {
            Some(scripts::SWAPPED) => Handover::Taken(user),
            _ => Handover::Missing,
        })
    }
}
