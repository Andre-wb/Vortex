use std::collections::BTreeSet;
use std::sync::Arc;

use fred::prelude::*;
use vortex_auth::account::user_id::UserId;
use vortex_core::room::room_id::RoomId;
use vortex_resume::error::{Result, StateError};
use vortex_resume::ports::upload_sessions::UploadSessions;
use vortex_resume::upload::chunk::ChunkIndex;
use vortex_resume::upload::file_name::FileName;
use vortex_resume::upload::identifier::UploadId;
use vortex_resume::upload::limits;
use vortex_resume::upload::session::Session;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::resume::scripts::{self, CLOSE, FIND, OPEN, SESSION_FIELDS, TAKE};

const SESSION: &str = "upload";
const CHUNKS: &str = "upload-chunks";
const INDEX: &str = "upload-index";

pub struct RedisUploadSessions {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
    lifetime: f64,
}

impl RedisUploadSessions {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        Self::lasting(backbone, limits::SESSION_LIFETIME_SECONDS)
    }

    pub fn lasting(backbone: Arc<RedisBackbone>, lifetime: f64) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisUploadSessions {
            backbone,
            space,
            lifetime,
        }
    }

    fn session_key(&self, id: &UploadId) -> String {
        self.space.member_key(SESSION, id.written())
    }

    fn chunks_key(&self, id: &UploadId) -> String {
        self.space.member_key(CHUNKS, id.written())
    }

    fn index_key(&self) -> String {
        self.space.key(INDEX)
    }

    fn keys_of(&self, id: &UploadId) -> Vec<String> {
        vec![self.session_key(id), self.chunks_key(id)]
    }

    fn drop_one(&self, id: &UploadId) -> Result<bool> {
        let mut keys = self.keys_of(id);
        keys.push(self.index_key());
        let token = id.written().to_owned();
        let existed = self
            .backbone
            .execute(
                "закрытие сессии загрузки",
                move |pool| {
                    let keys = keys.clone();
                    let args: Vec<Value> = vec![token.clone().into()];
                    async move { CLOSE.run::<i64>(&pool, keys, args).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(existed == 1)
    }
}

impl UploadSessions for RedisUploadSessions {
    fn open(&self, session: &Session) -> Result<()> {
        let mut keys = self.keys_of(session.id());
        keys.push(self.index_key());

        let life = scripts::seconds_of(self.lifetime);
        let mut args: Vec<Value> = vec![
            session.room().value().into(),
            session.owner().value().into(),
            session.file_name().written().to_owned().into(),
            (session.file_bytes() as i64).into(),
            (session.total_chunks() as i64).into(),
            session.file_digest().to_owned().into(),
            session.opened_at().into(),
            life.into(),
            session.deadline().into(),
            session.id().written().to_owned().into(),
        ];
        args.extend(
            session
                .received()
                .iter()
                .map(|chunk| Value::from(i64::from(*chunk))),
        );

        self.backbone
            .execute(
                "открытие сессии загрузки",
                move |pool| {
                    let keys = keys.clone();
                    let args = args.clone();
                    async move { OPEN.run::<i64>(&pool, keys, args).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn find(&self, id: &UploadId) -> Result<Option<Session>> {
        let keys = self.keys_of(id);
        let row = self
            .backbone
            .execute("чтение сессии загрузки", move |pool| {
                let keys = keys.clone();
                async move { FIND.run::<Vec<String>>(&pool, keys, Vec::new()).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(session_of(id, &row))
    }

    fn take_chunk(&self, id: &UploadId, chunk: ChunkIndex) -> Result<Option<Session>> {
        let keys = self.keys_of(id);
        let life = scripts::seconds_of(self.lifetime);
        let index = i64::from(chunk.value());
        let row = self
            .backbone
            .execute("приём куска загрузки", move |pool| {
                let keys = keys.clone();
                let args: Vec<Value> = vec![index.into(), life.into()];
                async move { TAKE.run::<Vec<String>>(&pool, keys, args).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(session_of(id, &row))
    }

    fn close(&self, id: &UploadId) -> Result<bool> {
        self.drop_one(id)
    }

    fn sweep(&self, now: f64) -> Result<Vec<UploadId>> {
        let index = self.index_key();
        let tokens = self
            .backbone
            .execute(
                "список просроченных загрузок",
                move |pool| {
                    let index = index.clone();
                    async move {
                        pool.zrangebyscore::<Vec<String>, _, _, _>(
                            index,
                            f64::NEG_INFINITY,
                            now,
                            false,
                            None,
                        )
                        .await
                    }
                },
            )
            .map_err(|_| StateError::Unavailable)?;

        let mut swept = Vec::new();
        for token in tokens {
            let Ok(id) = UploadId::parse(&token) else {
                continue;
            };
            self.drop_one(&id)?;
            swept.push(id);
        }
        Ok(swept)
    }

    fn count(&self) -> Result<usize> {
        let index = self.index_key();
        let total = self
            .backbone
            .execute("счёт сессий загрузки", move |pool| {
                let index = index.clone();
                async move { pool.zcard::<i64, _>(index).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(total.max(0) as usize)
    }
}

fn session_of(id: &UploadId, row: &[String]) -> Option<Session> {
    if row.len() < SESSION_FIELDS {
        return None;
    }
    let room = RoomId::of(row[0].parse().ok()?)?;
    let owner = UserId::of(row[1].parse().ok()?)?;
    let file_name = FileName::parse(&row[2]).ok()?;
    let file_bytes = row[3].parse().ok()?;
    let total_chunks = row[4].parse().ok()?;
    let opened_at = row[6].parse().ok()?;
    let received: BTreeSet<u32> = row[SESSION_FIELDS..]
        .iter()
        .filter_map(|held| held.parse().ok())
        .collect();

    Some(
        Session::opened(
            id.clone(),
            room,
            owner,
            file_name,
            file_bytes,
            total_chunks,
            row[5].clone(),
            opened_at,
        )
        .with_received(received),
    )
}
