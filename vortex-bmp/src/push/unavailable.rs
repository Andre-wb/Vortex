use crate::ports::push_registry::PushRegistry;
use crate::push::category::PushCategory;
use crate::push::refusal::{PushStateError, Result};
use crate::push::registration::Registration;
use crate::push::tally::Tally;
use crate::push::token::PushToken;

pub struct UnavailablePushRegistry;

impl UnavailablePushRegistry {
    pub fn new() -> Self {
        UnavailablePushRegistry
    }
}

impl Default for UnavailablePushRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PushRegistry for UnavailablePushRegistry {
    fn register(&self, _categories: &[PushCategory], _registration: &Registration) -> Result<()> {
        Err(PushStateError::Unavailable)
    }

    fn unregister(&self, _token: &PushToken) -> Result<usize> {
        Err(PushStateError::Unavailable)
    }

    fn registrations(&self, _category: PushCategory, _now: f64) -> Result<Vec<Registration>> {
        Err(PushStateError::Unavailable)
    }

    fn note_wake(&self) -> Result<u64> {
        Err(PushStateError::Unavailable)
    }

    fn tally(&self) -> Result<Tally> {
        Err(PushStateError::Unavailable)
    }
}
