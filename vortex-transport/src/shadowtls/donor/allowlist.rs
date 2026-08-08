use crate::shadowtls::donor::target::DonorTarget;

pub const DEFAULT_DONORS: [&str; 5] = [
    "www.google.com",
    "www.microsoft.com",
    "cloudflare.com",
    "www.apple.com",
    "www.amazon.com",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DonorAllowlist {
    targets: Vec<DonorTarget>,
}

impl Default for DonorAllowlist {
    fn default() -> Self {
        DonorAllowlist {
            targets: DEFAULT_DONORS
                .iter()
                .map(|host| DonorTarget::https(*host))
                .collect(),
        }
    }
}

impl DonorAllowlist {
    pub fn new(targets: Vec<DonorTarget>) -> Self {
        if targets.is_empty() {
            return DonorAllowlist::default();
        }
        DonorAllowlist { targets }
    }

    pub fn targets(&self) -> &[DonorTarget] {
        &self.targets
    }

    pub fn fallback(&self) -> &DonorTarget {
        &self.targets[0]
    }

    pub fn resolve(&self, requested: Option<&str>) -> &DonorTarget {
        requested
            .and_then(|host| self.targets.iter().find(|target| target.matches(host)))
            .unwrap_or_else(|| self.fallback())
    }
}

#[cfg(test)]
mod tests {
    use super::{DonorAllowlist, DEFAULT_DONORS};
    use crate::shadowtls::donor::target::DonorTarget;

    #[test]
    fn the_requested_name_is_honoured_when_it_is_allowed() {
        let allowlist = DonorAllowlist::default();
        assert_eq!(
            allowlist.resolve(Some("www.apple.com")).host,
            "www.apple.com"
        );
    }

    #[test]
    fn a_name_outside_the_list_never_becomes_a_destination() {
        let allowlist = DonorAllowlist::default();
        assert_eq!(
            allowlist.resolve(Some("attacker.example")),
            allowlist.fallback()
        );
        assert_eq!(allowlist.resolve(None), allowlist.fallback());
    }

    #[test]
    fn the_fallback_is_the_same_every_time() {
        let allowlist = DonorAllowlist::default();
        assert_eq!(allowlist.fallback().host, DEFAULT_DONORS[0]);
        assert_eq!(allowlist.resolve(None), allowlist.resolve(None));
    }

    #[test]
    fn an_empty_list_falls_back_to_the_built_in_donors() {
        assert_eq!(DonorAllowlist::new(Vec::new()), DonorAllowlist::default());
    }

    #[test]
    fn an_explicit_list_replaces_the_built_in_one() {
        let allowlist = DonorAllowlist::new(vec![DonorTarget::new("127.0.0.1", 9443)]);
        assert_eq!(allowlist.targets().len(), 1);
        assert_eq!(allowlist.resolve(Some("www.google.com")).port, 9443);
    }
}
