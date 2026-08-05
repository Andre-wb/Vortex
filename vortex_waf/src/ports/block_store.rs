//! Хранилище временных блокировок.

use crate::domain::block_record::BlockRecord;
use crate::domain::client_ip::ClientIp;
use crate::domain::timestamp::Timestamp;

pub trait BlockStore: Send + Sync {
    fn put(&self, ip: &ClientIp, record: BlockRecord);

    /// Активна ли блокировка на момент `now`. Просроченная запись удаляется.
    fn is_blocked(&self, ip: &ClientIp, now: Timestamp) -> bool;

    /// `true`, если запись существовала и была удалена.
    fn remove(&self, ip: &ClientIp) -> bool;

    fn list(&self) -> Vec<(ClientIp, BlockRecord)>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
