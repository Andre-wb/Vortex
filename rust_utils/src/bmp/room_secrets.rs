//! Room BMP secret store.
//! Maps room_id → HKDF-derived secret (NOT the room key).

use dashmap::DashMap;

/// Thread-safe store for room BMP secrets.
/// The server does NOT know the room key — only the HKDF-derived BMP secret
/// which is sufficient to compute mailbox IDs for deposits.
pub struct RoomSecretStore {
    secrets: DashMap<i64, String>,
}

impl RoomSecretStore {
    pub fn new() -> Self {
        Self { secrets: DashMap::new() }
    }

    /// Store a BMP secret for a room.
    pub fn set(&self, room_id: i64, secret_hex: String) {
        self.secrets.insert(room_id, secret_hex);
    }

    /// Get the BMP secret for a room.
    pub fn get(&self, room_id: i64) -> Option<String> {
        self.secrets.get(&room_id).map(|v| v.clone())
    }

    /// Remove a room's BMP secret.
    pub fn remove(&self, room_id: i64) {
        self.secrets.remove(&room_id);
    }

    /// Number of registered rooms.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

impl Default for RoomSecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_get() {
        let store = RoomSecretStore::new();
        store.set(42, "abcd1234".to_string());
        assert_eq!(store.get(42), Some("abcd1234".to_string()));
        assert_eq!(store.get(99), None);
    }

    #[test]
    fn test_remove() {
        let store = RoomSecretStore::new();
        store.set(1, "secret".to_string());
        store.remove(1);
        assert_eq!(store.get(1), None);
    }
}
