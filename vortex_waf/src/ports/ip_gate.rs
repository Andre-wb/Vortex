//! Проверка «пускать ли адрес» — только чтение.
//!
//! ISP: тому, кто лишь проверяет доступ (движок при анализе), не нужны методы
//! блокировки — они вынесены в [`crate::ports::ip_blocker::IpBlocker`].

use crate::domain::client_ip::ClientIp;

pub trait IpGate: Send + Sync {
    fn is_blocked(&self, ip: &ClientIp) -> bool;
}
