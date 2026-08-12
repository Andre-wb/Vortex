use crate::net::cidr::Cidr;
use std::net::IpAddr;

pub const SUSPECTED: [&str; 3] = ["109.124.0.0/16", "149.154.0.0/16", "185.228.0.0/16"];

pub const NOT_A_CENSOR: [&str; 4] = [
    "149.154.160.0/20",
    "149.154.164.0/22",
    "185.228.168.0/24",
    "185.228.169.0/24",
];

#[derive(Debug, Clone)]
pub struct CensorNetworks {
    suspected: Vec<Cidr>,
    excluded: Vec<Cidr>,
}

impl Default for CensorNetworks {
    fn default() -> Self {
        CensorNetworks {
            suspected: SUSPECTED
                .iter()
                .filter_map(|net| Cidr::parse(net))
                .collect(),
            excluded: NOT_A_CENSOR
                .iter()
                .filter_map(|net| Cidr::parse(net))
                .collect(),
        }
    }
}

impl CensorNetworks {
    pub fn of(suspected: &[&str], excluded: &[&str]) -> Self {
        CensorNetworks {
            suspected: suspected
                .iter()
                .filter_map(|net| Cidr::parse(net))
                .collect(),
            excluded: excluded.iter().filter_map(|net| Cidr::parse(net)).collect(),
        }
    }

    pub fn empty() -> Self {
        CensorNetworks {
            suspected: Vec::new(),
            excluded: Vec::new(),
        }
    }

    pub fn holding(&self, address: &IpAddr) -> Option<Cidr> {
        if self.excluded.iter().any(|net| net.contains(address)) {
            return None;
        }
        self.suspected
            .iter()
            .find(|net| net.contains(address))
            .copied()
    }

    pub fn len(&self) -> usize {
        self.suspected.len()
    }

    pub fn is_empty(&self) -> bool {
        self.suspected.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::CensorNetworks;
    use crate::net::address;

    fn holding(value: &str) -> Option<String> {
        CensorNetworks::default()
            .holding(&address::parse(value).unwrap())
            .map(|net| net.to_string())
    }

    #[test]
    fn an_address_inside_a_suspected_network_is_named_by_that_network() {
        assert_eq!(holding("109.124.1.1"), Some("109.124.0.0/16".to_owned()));
        assert_eq!(holding("149.154.1.1"), Some("149.154.0.0/16".to_owned()));
        assert_eq!(holding("185.228.1.1"), Some("185.228.0.0/16".to_owned()));
    }

    #[test]
    fn the_telegram_data_centre_is_not_censorship_infrastructure() {
        assert_eq!(holding("149.154.160.1"), None);
        assert_eq!(holding("149.154.167.99"), None);
        assert_eq!(holding("149.154.175.255"), None);
        assert_eq!(holding("149.154.164.1"), None);
    }

    #[test]
    fn a_public_dns_filter_is_not_censorship_infrastructure_either() {
        assert_eq!(holding("185.228.168.9"), None);
        assert_eq!(holding("185.228.169.9"), None);
    }

    #[test]
    fn an_ordinary_address_belongs_to_no_suspected_network() {
        assert_eq!(holding("203.0.113.7"), None);
        assert_eq!(holding("8.8.8.8"), None);
        assert_eq!(holding("2001:db8::1"), None);
    }

    #[test]
    fn a_registry_nobody_filled_accuses_nobody() {
        let empty = CensorNetworks::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.holding(&address::parse("109.124.1.1").unwrap()), None);
    }

    #[test]
    fn an_exclusion_wins_over_the_network_that_holds_it() {
        let networks = CensorNetworks::of(&["10.0.0.0/8"], &["10.1.0.0/16"]);
        assert!(networks
            .holding(&address::parse("10.2.0.1").unwrap())
            .is_some());
        assert_eq!(networks.holding(&address::parse("10.1.0.1").unwrap()), None);
    }
}
