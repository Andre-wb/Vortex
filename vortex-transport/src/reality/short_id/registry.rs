use crate::ports::short_id_registry::ShortIdRegistry;
use crate::reality::short_id::value::ShortId;
use std::sync::RwLock;
use subtle::{Choice, ConstantTimeEq};

#[derive(Debug, Default)]
pub struct MemoryShortIdRegistry {
    entries: RwLock<Vec<ShortId>>,
}

impl MemoryShortIdRegistry {
    pub fn new() -> Self {
        MemoryShortIdRegistry::default()
    }

    pub fn with_entries(entries: impl IntoIterator<Item = ShortId>) -> Self {
        MemoryShortIdRegistry {
            entries: RwLock::new(entries.into_iter().collect()),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<ShortId>> {
        self.entries.read().expect("реестр short_id отравлен")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Vec<ShortId>> {
        self.entries.write().expect("реестр short_id отравлен")
    }
}

impl ShortIdRegistry for MemoryShortIdRegistry {
    fn contains(&self, short_id: &ShortId) -> bool {
        let entries = self.read();
        let mut found = Choice::from(0u8);
        for entry in entries.iter() {
            let same_len = Choice::from(u8::from(entry.len() == short_id.len()));
            let same_bytes = if entry.len() == short_id.len() {
                entry.as_bytes().ct_eq(short_id.as_bytes())
            } else {
                Choice::from(0u8)
            };
            found |= same_len & same_bytes;
        }
        found.into()
    }

    fn insert(&self, short_id: ShortId) -> bool {
        let mut entries = self.write();
        if entries.iter().any(|entry| entry == &short_id) {
            return false;
        }
        entries.push(short_id);
        true
    }

    fn remove(&self, short_id: &ShortId) -> bool {
        let mut entries = self.write();
        let before = entries.len();
        entries.retain(|entry| entry != short_id);
        entries.len() != before
    }

    fn all(&self) -> Vec<ShortId> {
        self.read().clone()
    }

    fn len(&self) -> usize {
        self.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryShortIdRegistry;
    use crate::ports::short_id_registry::ShortIdRegistry;
    use crate::reality::short_id::value::ShortId;

    fn id(hex: &str) -> ShortId {
        ShortId::from_hex(hex).unwrap()
    }

    #[test]
    fn stores_and_finds_entries() {
        let registry = MemoryShortIdRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.insert(id("deadbeef")));
        assert!(registry.contains(&id("deadbeef")));
        assert!(!registry.contains(&id("cafebabe")));
    }

    #[test]
    fn insert_is_idempotent() {
        let registry = MemoryShortIdRegistry::new();
        assert!(registry.insert(id("deadbeef")));
        assert!(!registry.insert(id("deadbeef")));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn remove_reports_whether_anything_was_dropped() {
        let registry = MemoryShortIdRegistry::with_entries([id("deadbeef")]);
        assert!(registry.remove(&id("deadbeef")));
        assert!(!registry.remove(&id("deadbeef")));
        assert!(registry.is_empty());
    }

    #[test]
    fn entries_of_other_lengths_never_match() {
        let registry = MemoryShortIdRegistry::with_entries([id("dead")]);
        assert!(!registry.contains(&id("deadbeef")));
        assert!(registry.contains(&id("dead")));
    }
}
