//! Чёрный список адресов: блокировка без срока действия.

use crate::domain::client_ip::ClientIp;

pub trait IpDenyList: Send + Sync {
    fn contains(&self, ip: &ClientIp) -> bool;

    fn add(&self, ip: ClientIp) -> bool;

    fn remove(&self, ip: &ClientIp) -> bool;

    fn list(&self) -> Vec<ClientIp>;
}
