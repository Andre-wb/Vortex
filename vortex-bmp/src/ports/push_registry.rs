use crate::push::category::PushCategory;
use crate::push::refusal::Result;
use crate::push::registration::Registration;
use crate::push::tally::Tally;
use crate::push::token::PushToken;

pub trait PushRegistry: Send + Sync {
    fn register(&self, categories: &[PushCategory], registration: &Registration) -> Result<()>;

    fn unregister(&self, token: &PushToken) -> Result<usize>;

    fn registrations(&self, category: PushCategory, now: f64) -> Result<Vec<Registration>>;

    fn note_wake(&self) -> Result<u64>;

    fn tally(&self) -> Result<Tally>;
}
