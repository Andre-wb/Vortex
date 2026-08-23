use crate::call::call_id::CallId;
use crate::call::record::Call;
use crate::error::Result;
use crate::store::swapped::Swapped;

pub trait CallRecords: Send + Sync {
    fn open(&self, call: &Call, now: f64) -> Result<()>;

    fn find(&self, call: &CallId, now: f64) -> Result<Option<Call>>;

    fn swap(&self, call: &CallId, expected: &Call, replacement: &Call, now: f64)
        -> Result<Swapped>;

    fn forget(&self, call: &CallId, now: f64) -> Result<bool>;
}
