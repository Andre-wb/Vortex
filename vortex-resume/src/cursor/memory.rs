use std::collections::HashMap;

use parking_lot::Mutex;

use crate::cursor::cursor::Cursor;
use crate::cursor::identifier::ClientKey;
use crate::error::Result;
use crate::ports::session_cursors::SessionCursors;

pub struct MemorySessionCursors {
    cursors: Mutex<HashMap<ClientKey, Cursor>>,
}

impl MemorySessionCursors {
    pub fn new() -> Self {
        MemorySessionCursors {
            cursors: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemorySessionCursors {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionCursors for MemorySessionCursors {
    fn save(&self, cursor: &Cursor) -> Result<()> {
        self.cursors
            .lock()
            .insert(cursor.key().clone(), cursor.clone());
        Ok(())
    }

    fn find(&self, key: &ClientKey) -> Result<Option<Cursor>> {
        Ok(self.cursors.lock().get(key).cloned())
    }

    fn forget(&self, key: &ClientKey) -> Result<bool> {
        Ok(self.cursors.lock().remove(key).is_some())
    }

    fn count(&self) -> Result<usize> {
        Ok(self.cursors.lock().len())
    }
}
