use crate::secret::value::BmpSecret;

pub trait RoomSecrets: Send + Sync {
    fn set(&self, room_id: i64, secret: BmpSecret);

    fn get(&self, room_id: i64) -> Option<BmpSecret>;

    fn remove(&self, room_id: i64);

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
