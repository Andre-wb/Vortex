use crate::push::limits;
use crate::push::refusal::PushRefusal;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PushEndpoint(String);

impl PushEndpoint {
    pub fn parse(value: &str) -> Result<Self, PushRefusal> {
        if value.chars().count() < limits::MIN_ENDPOINT_LENGTH {
            return Err(PushRefusal::ShortEndpoint);
        }
        if value.chars().count() > limits::MAX_ENDPOINT_LENGTH {
            return Err(PushRefusal::OverLongEndpoint);
        }
        if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(PushRefusal::EndpointOutsideAlphabet);
        }
        Ok(PushEndpoint(value.to_owned()))
    }

    pub fn written(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::PushEndpoint;
    use crate::push::refusal::PushRefusal;

    #[test]
    fn a_provider_url_names_an_endpoint() {
        let value = "https://fcm.googleapis.com/fcm/send/abc";
        assert_eq!(PushEndpoint::parse(value).unwrap().written(), value);
    }

    #[test]
    fn a_short_endpoint_is_refused() {
        assert_eq!(
            PushEndpoint::parse("https://"),
            Err(PushRefusal::ShortEndpoint)
        );
    }

    #[test]
    fn an_endpoint_with_a_space_is_refused() {
        assert_eq!(
            PushEndpoint::parse("https://a b.example/x"),
            Err(PushRefusal::EndpointOutsideAlphabet)
        );
    }
}
