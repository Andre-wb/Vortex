//! Изменение состояния блокировок — только запись.

use crate::domain::client_ip::ClientIp;

pub trait IpBlocker: Send + Sync {
    /// `false`, если адрес в белом списке и блокировка отклонена.
    fn block(&self, ip: &ClientIp, reason: &str, duration_secs: u64) -> bool;

    /// `false`, если активной блокировки не было.
    fn unblock(&self, ip: &ClientIp) -> bool;
}
