use crate::attempt::subject::Subject;
use crate::error::Result;

pub trait StrikeLedger: Send + Sync {
    fn strike(&self, subject: &Subject) -> Result<u32>;
}
