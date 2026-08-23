use crate::registry::address::PeerAddress;
use crate::registry::name::PeerName;
use crate::registry::pubkey::NodePubkey;

#[derive(Debug, Clone, PartialEq)]
pub struct PeerRecord {
    address: PeerAddress,
    name: PeerName,
    port: u16,
    pubkey: Option<NodePubkey>,
    last_seen: f64,
}

impl PeerRecord {
    pub fn seen(
        address: PeerAddress,
        name: PeerName,
        port: u16,
        pubkey: Option<NodePubkey>,
        last_seen: f64,
    ) -> Self {
        PeerRecord {
            address,
            name,
            port,
            pubkey,
            last_seen,
        }
    }

    pub fn address(&self) -> &PeerAddress {
        &self.address
    }

    pub fn name(&self) -> &PeerName {
        &self.name
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn pubkey(&self) -> Option<&NodePubkey> {
        self.pubkey.as_ref()
    }

    pub fn last_seen(&self) -> f64 {
        self.last_seen
    }

    pub fn encrypted(&self) -> bool {
        self.pubkey.is_some()
    }

    pub fn alive(&self, now: f64, timeout: f64) -> bool {
        now - self.last_seen < timeout
    }

    pub fn age(&self, now: f64) -> f64 {
        ((now - self.last_seen) * 10.0).round() / 10.0
    }

    pub fn refreshed(
        &self,
        name: PeerName,
        port: u16,
        pubkey: Option<NodePubkey>,
        now: f64,
    ) -> Self {
        PeerRecord {
            address: self.address.clone(),
            name,
            port,
            pubkey: pubkey.or_else(|| self.pubkey.clone()),
            last_seen: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PeerRecord;
    use crate::registry::address::PeerAddress;
    use crate::registry::name::PeerName;
    use crate::registry::pubkey::NodePubkey;

    fn record(last_seen: f64) -> PeerRecord {
        PeerRecord::seen(
            PeerAddress::parse("10.0.0.5").unwrap(),
            PeerName::parse("laptop").unwrap(),
            8000,
            None,
            last_seen,
        )
    }

    #[test]
    fn a_peer_is_alive_until_the_timeout_and_not_at_it() {
        let seen = record(1000.0);
        assert!(seen.alive(1029.9, 30.0));
        assert!(!seen.alive(1030.0, 30.0));
    }

    #[test]
    fn an_age_is_told_to_one_decimal_place() {
        assert_eq!(record(1000.0).age(1002.46), 2.5);
    }

    #[test]
    fn a_refresh_keeps_a_key_the_newcomer_did_not_bring() {
        let key = NodePubkey::parse(&"ab".repeat(32)).unwrap();
        let known = record(1000.0).refreshed(
            PeerName::parse("laptop").unwrap(),
            8000,
            Some(key.clone()),
            1001.0,
        );
        let again = known.refreshed(PeerName::parse("laptop").unwrap(), 8000, None, 1002.0);
        assert_eq!(again.pubkey(), Some(&key));
        assert_eq!(again.last_seen(), 1002.0);
    }

    #[test]
    fn a_refresh_replaces_a_key_the_newcomer_did_bring() {
        let first = NodePubkey::parse(&"ab".repeat(32)).unwrap();
        let second = NodePubkey::parse(&"cd".repeat(32)).unwrap();
        let known = record(1000.0).refreshed(
            PeerName::parse("laptop").unwrap(),
            8000,
            Some(first),
            1001.0,
        );
        let again = known.refreshed(
            PeerName::parse("laptop").unwrap(),
            8000,
            Some(second.clone()),
            1002.0,
        );
        assert_eq!(again.pubkey(), Some(&second));
    }
}
