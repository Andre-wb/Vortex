//! Чёрный список адресов в памяти.

use crate::domain::client_ip::ClientIp;
use crate::ports::ip_deny_list::IpDenyList;
use std::collections::BTreeSet;
use std::sync::RwLock;

#[derive(Debug, Default)]
pub struct InMemoryDenyList {
    ips: RwLock<BTreeSet<ClientIp>>,
}

impl InMemoryDenyList {
    pub fn new<I, S>(ips: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<ClientIp>,
    {
        InMemoryDenyList {
            ips: RwLock::new(ips.into_iter().map(Into::into).collect()),
        }
    }

    pub fn empty() -> Self {
        InMemoryDenyList::default()
    }
}

impl IpDenyList for InMemoryDenyList {
    fn contains(&self, ip: &ClientIp) -> bool {
        self.ips
            .read()
            .expect("чёрный список отравлен")
            .contains(ip)
    }

    fn add(&self, ip: ClientIp) -> bool {
        self.ips.write().expect("чёрный список отравлен").insert(ip)
    }

    fn remove(&self, ip: &ClientIp) -> bool {
        self.ips.write().expect("чёрный список отравлен").remove(ip)
    }

    fn list(&self) -> Vec<ClientIp> {
        self.ips
            .read()
            .expect("чёрный список отравлен")
            .iter()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryDenyList;
    use crate::domain::client_ip::ClientIp;
    use crate::ports::ip_deny_list::IpDenyList;

    #[test]
    fn membership_round_trips() {
        let list = InMemoryDenyList::new(["6.6.6.6"]);
        assert!(list.contains(&ClientIp::from("6.6.6.6")));
        assert!(list.remove(&ClientIp::from("6.6.6.6")));
        assert!(!list.contains(&ClientIp::from("6.6.6.6")));
    }
}
