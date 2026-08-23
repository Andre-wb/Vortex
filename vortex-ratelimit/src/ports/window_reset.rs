use crate::attempt::subject::Subject;
use crate::error::Result;

pub trait WindowReset: Send + Sync {
    fn forget(&self, subject: &Subject) -> Result<()>;
}
