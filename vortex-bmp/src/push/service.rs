use std::sync::Arc;

use crate::ports::push_registry::PushRegistry;
use crate::push::category::PushCategory;
use crate::push::endpoint::PushEndpoint;
use crate::push::limits;
use crate::push::refusal::{PushRefusal, Result};
use crate::push::registration::Registration;
use crate::push::tally::Tally;
use crate::push::token::PushToken;

pub struct PushProxyService {
    registry: Arc<dyn PushRegistry>,
}

impl PushProxyService {
    pub fn new(registry: Arc<dyn PushRegistry>) -> Self {
        PushProxyService { registry }
    }

    pub fn categories_of(asked: &[i64]) -> std::result::Result<Vec<PushCategory>, PushRefusal> {
        if asked.is_empty() {
            return Err(PushRefusal::NoCategories);
        }
        if asked.len() > usize::from(limits::CATEGORY_COUNT) {
            return Err(PushRefusal::TooManyCategories);
        }
        Ok(asked
            .iter()
            .map(|value| PushCategory::wrapping(*value))
            .collect())
    }

    pub fn register(
        &self,
        categories: &[PushCategory],
        token: PushToken,
        endpoint: PushEndpoint,
        now: f64,
    ) -> Result<()> {
        let made = Registration::made(token, endpoint, now);
        self.registry.register(categories, &made)
    }

    pub fn unregister(&self, token: &PushToken) -> Result<usize> {
        self.registry.unregister(token)
    }

    pub fn woken(&self, category: PushCategory, now: f64) -> Result<Vec<Registration>> {
        self.registry.note_wake()?;
        self.registry.registrations(category, now)
    }

    pub fn registrations(&self, category: PushCategory, now: f64) -> Result<Vec<Registration>> {
        self.registry.registrations(category, now)
    }

    pub fn tally(&self) -> Result<Tally> {
        self.registry.tally()
    }
}
