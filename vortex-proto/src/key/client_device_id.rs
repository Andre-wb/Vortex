pub const CLIENT_DEVICE_ID_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientDeviceId(String);

impl ClientDeviceId {
    pub fn parse(value: &str) -> Option<Self> {
        if value.len() != CLIENT_DEVICE_ID_LEN {
            return None;
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        Some(ClientDeviceId(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientDeviceId, CLIENT_DEVICE_ID_LEN};

    #[test]
    fn a_well_formed_identifier_is_accepted() {
        let value = "0123456789abcdef0123456789abcdef";
        assert_eq!(ClientDeviceId::parse(value).unwrap().as_str(), value);
    }

    #[test]
    fn an_identifier_of_another_length_is_refused() {
        assert!(ClientDeviceId::parse(&"a".repeat(CLIENT_DEVICE_ID_LEN - 1)).is_none());
        assert!(ClientDeviceId::parse(&"a".repeat(CLIENT_DEVICE_ID_LEN + 1)).is_none());
    }

    #[test]
    fn upper_case_is_refused() {
        assert!(ClientDeviceId::parse("0123456789ABCDEF0123456789abcdef").is_none());
    }

    #[test]
    fn a_multibyte_identifier_is_refused_and_measured_in_bytes() {
        assert!(ClientDeviceId::parse(&"ф".repeat(16)).is_none());
    }
}
