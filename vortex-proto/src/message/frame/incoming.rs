use serde_json::{Map, Value};

#[derive(Clone, Debug, Default)]
pub struct IncomingFrame(Map<String, Value>);

impl IncomingFrame {
    pub fn from_json(payload: &str) -> Option<Self> {
        match serde_json::from_str(payload).ok()? {
            Value::Object(fields) => Some(IncomingFrame(fields)),
            _ => None,
        }
    }

    pub fn of(fields: Map<String, Value>) -> Self {
        IncomingFrame(fields)
    }

    pub fn field(&self, name: &str) -> Option<&Value> {
        self.0.get(name).filter(|value| !value.is_null())
    }

    pub fn text(&self, name: &str) -> &str {
        self.field(name).and_then(Value::as_str).unwrap_or("")
    }

    pub fn scalar_text(&self, name: &str) -> String {
        match self.field(name) {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Number(number)) => number.to_string(),
            _ => String::new(),
        }
    }

    pub fn action(&self) -> &str {
        self.text("action")
    }
}

#[cfg(test)]
mod tests {
    use super::IncomingFrame;

    #[test]
    fn a_frame_is_read_out_of_an_object() {
        let frame = IncomingFrame::from_json(r#"{"action":"message","ciphertext":"ab"}"#).unwrap();
        assert_eq!(frame.action(), "message");
        assert_eq!(frame.text("ciphertext"), "ab");
    }

    #[test]
    fn anything_that_is_not_an_object_is_not_a_frame() {
        assert!(IncomingFrame::from_json("[]").is_none());
        assert!(IncomingFrame::from_json("\"message\"").is_none());
        assert!(IncomingFrame::from_json("not json").is_none());
    }

    #[test]
    fn an_absent_field_reads_as_an_empty_string() {
        let frame = IncomingFrame::from_json(r#"{"action":"message"}"#).unwrap();
        assert_eq!(frame.text("ciphertext"), "");
        assert!(frame.field("ciphertext").is_none());
    }

    #[test]
    fn a_null_field_is_the_same_as_an_absent_one() {
        let frame = IncomingFrame::from_json(r#"{"ciphertext":null}"#).unwrap();
        assert!(frame.field("ciphertext").is_none());
    }

    #[test]
    fn a_field_of_another_kind_reads_as_an_empty_string() {
        let frame = IncomingFrame::from_json(r#"{"ciphertext":12}"#).unwrap();
        assert_eq!(frame.text("ciphertext"), "");
    }

    #[test]
    fn a_client_identifier_is_read_whether_it_is_written_as_text_or_as_a_number() {
        let text = IncomingFrame::from_json(r#"{"msg_id":"a-1"}"#).unwrap();
        let number = IncomingFrame::from_json(r#"{"msg_id":12}"#).unwrap();
        let missing = IncomingFrame::from_json("{}").unwrap();
        assert_eq!(text.scalar_text("msg_id"), "a-1");
        assert_eq!(number.scalar_text("msg_id"), "12");
        assert_eq!(missing.scalar_text("msg_id"), "");
    }
}
