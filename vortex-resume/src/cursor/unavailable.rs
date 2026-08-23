use crate::cursor::cursor::Cursor;
use crate::cursor::identifier::ClientKey;
use crate::error::{Result, StateError};
use crate::ports::session_cursors::SessionCursors;

pub struct UnavailableSessionCursors;

impl UnavailableSessionCursors {
    pub fn new() -> Self {
        UnavailableSessionCursors
    }
}

impl Default for UnavailableSessionCursors {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionCursors for UnavailableSessionCursors {
    fn save(&self, _cursor: &Cursor) -> Result<()> {
        Err(StateError::Unavailable)
    }

    fn find(&self, _key: &ClientKey) -> Result<Option<Cursor>> {
        Err(StateError::Unavailable)
    }

    fn forget(&self, _key: &ClientKey) -> Result<bool> {
        Err(StateError::Unavailable)
    }

    fn count(&self) -> Result<usize> {
        Err(StateError::Unavailable)
    }
}
