use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload(String);

impl Payload {
    pub fn of(text: &str) -> Self {
        Payload(text.to_owned())
    }

    pub fn written(&self) -> &str {
        &self.0
    }

    pub fn into_written(self) -> String {
        self.0
    }

    pub fn read(&self) -> Option<Value> {
        serde_json::from_str(&self.0).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::Payload;

    #[test]
    fn a_payload_is_kept_verbatim() {
        let payload = Payload::of("{\"type\":\"message\"}");
        assert_eq!(payload.written(), "{\"type\":\"message\"}");
        assert_eq!(payload.read().unwrap()["type"], "message");
    }

    #[test]
    fn text_that_is_not_json_reads_as_nothing() {
        assert!(Payload::of("not json").read().is_none());
    }
}
