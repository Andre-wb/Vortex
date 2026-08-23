use crate::cursor::cursor::Cursor;
use crate::cursor::identifier::ClientKey;
use crate::error::Result;

pub trait SessionCursors: Send + Sync {
    fn save(&self, cursor: &Cursor) -> Result<()>;

    fn find(&self, key: &ClientKey) -> Result<Option<Cursor>>;

    fn forget(&self, key: &ClientKey) -> Result<bool>;

    fn count(&self) -> Result<usize>;
}
