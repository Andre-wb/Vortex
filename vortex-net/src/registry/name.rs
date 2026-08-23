use crate::registry::limits;
use crate::registry::refusal::PeerRefusal;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerName(String);

impl PeerName {
    pub fn parse(value: &str) -> Result<Self, PeerRefusal> {
        if value.is_empty() {
            return Err(PeerRefusal::EmptyName);
        }
        if value.chars().count() > limits::MAX_NAME_LENGTH {
            return Err(PeerRefusal::OverLongName);
        }
        if value.chars().any(|c| c.is_control() || c == ':') {
            return Err(PeerRefusal::NameOutsideAlphabet);
        }
        Ok(PeerName(value.to_owned()))
    }

    pub fn written(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::PeerName;
    use crate::registry::refusal::PeerRefusal;

    #[test]
    fn a_host_name_names_a_peer() {
        assert_eq!(
            PeerName::parse("vortex-laptop").unwrap().written(),
            "vortex-laptop"
        );
    }

    #[test]
    fn an_empty_name_is_refused() {
        assert_eq!(PeerName::parse(""), Err(PeerRefusal::EmptyName));
    }

    #[test]
    fn a_name_that_would_split_a_stored_record_is_refused() {
        assert_eq!(
            PeerName::parse("a:b"),
            Err(PeerRefusal::NameOutsideAlphabet)
        );
        assert_eq!(
            PeerName::parse("a\nb"),
            Err(PeerRefusal::NameOutsideAlphabet)
        );
    }
}
