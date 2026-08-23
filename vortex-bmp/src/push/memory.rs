use std::collections::BTreeMap;

use parking_lot::Mutex;

use crate::ports::push_registry::PushRegistry;
use crate::push::category::PushCategory;
use crate::push::limits;
use crate::push::refusal::Result;
use crate::push::registration::Registration;
use crate::push::tally::Tally;
use crate::push::token::PushToken;

#[derive(Default)]
struct Shelf {
    categories: BTreeMap<u8, Vec<Registration>>,
    wakes: u64,
}

pub struct MemoryPushRegistry {
    shelf: Mutex<Shelf>,
    depth: usize,
}

impl MemoryPushRegistry {
    pub fn new() -> Self {
        Self::sized(limits::MAX_TOKENS_PER_CATEGORY)
    }

    pub fn sized(depth: usize) -> Self {
        MemoryPushRegistry {
            shelf: Mutex::new(Shelf::default()),
            depth,
        }
    }
}

impl Default for MemoryPushRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PushRegistry for MemoryPushRegistry {
    fn register(&self, categories: &[PushCategory], registration: &Registration) -> Result<()> {
        let mut shelf = self.shelf.lock();
        for category in categories {
            let held = shelf.categories.entry(category.value()).or_default();
            held.retain(|made| made.token() != registration.token());
            if held.len() < self.depth {
                held.push(registration.clone());
            }
        }
        Ok(())
    }

    fn unregister(&self, token: &PushToken) -> Result<usize> {
        let mut shelf = self.shelf.lock();
        let mut dropped = 0;
        for held in shelf.categories.values_mut() {
            let before = held.len();
            held.retain(|made| made.token() != token);
            dropped += before - held.len();
        }
        Ok(dropped)
    }

    fn registrations(&self, category: PushCategory, now: f64) -> Result<Vec<Registration>> {
        let mut shelf = self.shelf.lock();
        let held = shelf.categories.entry(category.value()).or_default();
        held.retain(|made| !made.stale(now));
        Ok(held.clone())
    }

    fn note_wake(&self) -> Result<u64> {
        let mut shelf = self.shelf.lock();
        shelf.wakes += 1;
        Ok(shelf.wakes)
    }

    fn tally(&self) -> Result<Tally> {
        let shelf = self.shelf.lock();
        let tokens = shelf.categories.values().map(Vec::len).sum();
        let categories = shelf
            .categories
            .values()
            .filter(|held| !held.is_empty())
            .count();
        Ok(Tally::of(tokens, categories, shelf.wakes))
    }
}
