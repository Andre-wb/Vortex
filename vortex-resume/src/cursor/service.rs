use std::sync::Arc;

use crate::cursor::cursor::Cursor;
use crate::cursor::identifier::ClientKey;
use crate::error::Result;
use crate::ports::session_cursors::SessionCursors;

pub struct SessionCursorService {
    cursors: Arc<dyn SessionCursors>,
}

impl SessionCursorService {
    pub fn new(cursors: Arc<dyn SessionCursors>) -> Self {
        SessionCursorService { cursors }
    }

    pub fn save(
        &self,
        key: ClientKey,
        mailbox_stamp: f64,
        rooms: &[i64],
        now: f64,
    ) -> Result<Cursor> {
        let cursor = Cursor::of(key, mailbox_stamp, rooms, now);
        self.cursors.save(&cursor)?;
        Ok(cursor)
    }

    pub fn find(&self, key: &ClientKey, now: f64) -> Result<Option<Cursor>> {
        let Some(cursor) = self.cursors.find(key)? else {
            return Ok(None);
        };
        if cursor.stale(now) {
            self.cursors.forget(key)?;
            return Ok(None);
        }
        Ok(Some(cursor))
    }

    pub fn forget(&self, key: &ClientKey) -> Result<bool> {
        self.cursors.forget(key)
    }

    pub fn count(&self) -> Result<usize> {
        self.cursors.count()
    }
}
