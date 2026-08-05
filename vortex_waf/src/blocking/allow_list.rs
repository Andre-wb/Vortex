//! Белый список адресов в памяти.

use crate::domain::client_ip::ClientIp;
use crate::ports::ip_allow_list::IpAllowList;
use std::collections::BTreeSet;
use std::sync::RwLock;

#[derive(Debug, Default)]
pub struct InMemoryAllowList {
    ips: RwLock<BTreeSet<ClientIp>>,
}

impl InMemoryAllowList {
    pub fn new<I, S>(ips: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<ClientIp>,
    {
        InMemoryAllowList {
            ips: RwLock::new(ips.into_iter().map(Into::into).collect()),
        }
    }

    /// Локальные адреса — состав по умолчанию.
    pub fn with_loopback() -> Self {
        InMemoryAllowList::new(["127.0.0.1", "::1", "localhost"])
    }

    pub fn empty() -> Self {
        InMemoryAllowList::default()
    }
}

impl IpAllowList for InMemoryAllowList {
    fn contains(&self, ip: &ClientIp) -> bool {
        self.ips.read().expect("белый список отравлен").contains(ip)
    }

    fn add(&self, ip: ClientIp) -> bool {
        self.ips.write().expect("белый список отравлен").insert(ip)
    }

    fn remove(&self, ip: &ClientIp) -> bool {
        self.ips.write().expect("белый список отравлен").remove(ip)
    }

    fn list(&self) -> Vec<ClientIp> {
        self.ips
            .read()
            .expect("белый список отравлен")
            .iter()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryAllowList;
    use crate::domain::client_ip::ClientIp;
    use crate::ports::ip_allow_list::IpAllowList;

    #[test]
    fn loopback_is_allowed_by_default() {
        let list = InMemoryAllowList::with_loopback();
        assert!(list.contains(&ClientIp::from("127.0.0.1")));
        assert!(list.contains(&ClientIp::from("::1")));
        assert!(!list.contains(&ClientIp::from("8.8.8.8")));
    }

    #[test]
    fn add_and_remove_report_change() {
        let list = InMemoryAllowList::empty();
        assert!(list.add(ClientIp::from("10.0.0.1")));
        assert!(!list.add(ClientIp::from("10.0.0.1")));
        assert!(list.remove(&ClientIp::from("10.0.0.1")));
        assert!(!list.remove(&ClientIp::from("10.0.0.1")));
        assert!(list.list().is_empty());
    }
}
