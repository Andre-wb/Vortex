//! Белый список адресов: их не блокируют и не ограничивают по частоте.

use crate::domain::client_ip::ClientIp;

pub trait IpAllowList: Send + Sync {
    fn contains(&self, ip: &ClientIp) -> bool;

    fn add(&self, ip: ClientIp) -> bool;

    fn remove(&self, ip: &ClientIp) -> bool;

    fn list(&self) -> Vec<ClientIp>;
}
