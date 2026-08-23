use std::sync::Arc;

use fred::prelude::*;
use vortex_resume::cursor::cursor::Cursor;
use vortex_resume::cursor::identifier::ClientKey;
use vortex_resume::cursor::limits;
use vortex_resume::error::{Result, StateError};
use vortex_resume::ports::session_cursors::SessionCursors;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::resume::scripts::{self, FIND_CURSOR, FORGET_CURSOR, SAVE_CURSOR};

const CURSOR: &str = "cursor";
const INDEX: &str = "cursor-index";
const CURSOR_FIELDS: usize = 3;

pub struct RedisSessionCursors {
    backbone: Arc<RedisBackbone>,
    space: KeySpace,
    lifetime: f64,
}

impl RedisSessionCursors {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        Self::lasting(backbone, limits::CURSOR_LIFETIME_SECONDS)
    }

    pub fn lasting(backbone: Arc<RedisBackbone>, lifetime: f64) -> Self {
        let space = backbone.key_space(scripts::DOMAIN);
        RedisSessionCursors {
            backbone,
            space,
            lifetime,
        }
    }

    fn cursor_key(&self, key: &ClientKey) -> String {
        self.space.member_key(CURSOR, key.written())
    }

    fn index_key(&self) -> String {
        self.space.key(INDEX)
    }

    fn keys_of(&self, key: &ClientKey) -> Vec<String> {
        vec![self.cursor_key(key), self.index_key()]
    }
}

impl SessionCursors for RedisSessionCursors {
    fn save(&self, cursor: &Cursor) -> Result<()> {
        let keys = self.keys_of(cursor.key());
        let life = scripts::seconds_of(self.lifetime);
        let rooms = scripts::rooms_written(cursor.rooms());
        let stamp = cursor.mailbox_stamp();
        let saved = cursor.saved_at();
        let named = cursor.key().written().to_owned();

        self.backbone
            .execute("запись курсора переноса", move |pool| {
                let keys = keys.clone();
                let args: Vec<Value> = vec![
                    stamp.into(),
                    rooms.clone().into(),
                    saved.into(),
                    life.into(),
                    named.clone().into(),
                ];
                async move { SAVE_CURSOR.run::<i64>(&pool, keys, args).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(())
    }

    fn find(&self, key: &ClientKey) -> Result<Option<Cursor>> {
        let keys = self.keys_of(key);
        let named = key.written().to_owned();
        let row = self
            .backbone
            .execute("чтение курсора переноса", move |pool| {
                let keys = keys.clone();
                let args: Vec<Value> = vec![named.clone().into()];
                async move { FIND_CURSOR.run::<Vec<String>>(&pool, keys, args).await }
            })
            .map_err(|_| StateError::Unavailable)?;

        if row.len() < CURSOR_FIELDS {
            return Ok(None);
        }
        let (Ok(stamp), Ok(saved)) = (row[0].parse::<f64>(), row[2].parse::<f64>()) else {
            return Ok(None);
        };
        Ok(Some(Cursor::of(
            key.clone(),
            stamp,
            &scripts::rooms_read(&row[1]),
            saved,
        )))
    }

    fn forget(&self, key: &ClientKey) -> Result<bool> {
        let keys = self.keys_of(key);
        let named = key.written().to_owned();
        let existed = self
            .backbone
            .execute(
                "удаление курсора переноса",
                move |pool| {
                    let keys = keys.clone();
                    let args: Vec<Value> = vec![named.clone().into()];
                    async move { FORGET_CURSOR.run::<i64>(&pool, keys, args).await }
                },
            )
            .map_err(|_| StateError::Unavailable)?;
        Ok(existed == 1)
    }

    fn count(&self) -> Result<usize> {
        let index = self.index_key();
        let total = self
            .backbone
            .execute("счёт курсоров переноса", move |pool| {
                let index = index.clone();
                async move { pool.scard::<i64, _>(index).await }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(total.max(0) as usize)
    }
}
