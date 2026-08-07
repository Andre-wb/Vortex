use dashmap::DashMap;

use crate::ports::room_secrets::RoomSecrets;
use crate::secret::value::BmpSecret;

#[derive(Default)]
pub struct MemoryRoomSecrets {
    secrets: DashMap<i64, BmpSecret>,
}

impl MemoryRoomSecrets {
    pub fn new() -> Self {
        MemoryRoomSecrets {
            secrets: DashMap::new(),
        }
    }
}

impl RoomSecrets for MemoryRoomSecrets {
    fn set(&self, room_id: i64, secret: BmpSecret) {
        self.secrets.insert(room_id, secret);
    }

    fn get(&self, room_id: i64) -> Option<BmpSecret> {
        self.secrets.get(&room_id).map(|entry| entry.clone())
    }

    fn remove(&self, room_id: i64) {
        self.secrets.remove(&room_id);
    }

    fn len(&self) -> usize {
        self.secrets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryRoomSecrets;
    use crate::ports::room_secrets::RoomSecrets;
    use crate::secret::value::BmpSecret;

    fn secret(byte: &str) -> BmpSecret {
        BmpSecret::parse(&byte.repeat(32)).unwrap()
    }

    #[test]
    fn a_registered_secret_comes_back_for_its_room() {
        let store = MemoryRoomSecrets::new();
        store.set(42, secret("ab"));
        assert_eq!(store.get(42), Some(secret("ab")));
        assert_eq!(store.get(99), None);
    }

    #[test]
    fn registering_again_replaces_the_previous_secret() {
        let store = MemoryRoomSecrets::new();
        store.set(1, secret("ab"));
        store.set(1, secret("cd"));
        assert_eq!(store.get(1), Some(secret("cd")));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_removed_secret_is_gone() {
        let store = MemoryRoomSecrets::new();
        store.set(1, secret("ab"));
        store.remove(1);
        assert_eq!(store.get(1), None);
        assert!(store.is_empty());
    }
}
