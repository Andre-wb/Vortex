use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageId(i64);

impl MessageId {
    pub fn read(value: Option<&Value>) -> Option<Self> {
        match value? {
            Value::Number(number) => number.as_i64().map(MessageId),
            Value::String(text) => text.trim().parse::<i64>().ok().map(MessageId),
            _ => None,
        }
    }

    pub fn value(&self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::MessageId;
    use serde_json::json;

    fn read(value: serde_json::Value) -> Option<i64> {
        MessageId::read(Some(&value)).map(|id| id.value())
    }

    #[test]
    fn a_whole_number_is_an_identifier() {
        assert_eq!(read(json!(12)), Some(12));
        assert_eq!(read(json!(0)), Some(0));
        assert_eq!(read(json!(-3)), Some(-3));
    }

    #[test]
    fn a_number_written_as_a_string_is_an_identifier() {
        assert_eq!(read(json!("12")), Some(12));
        assert_eq!(read(json!(" 12 ")), Some(12));
        assert_eq!(read(json!("-3")), Some(-3));
    }

    #[test]
    fn a_string_that_is_not_a_number_is_not_an_identifier() {
        assert_eq!(read(json!("")), None);
        assert_eq!(read(json!("abc")), None);
        assert_eq!(read(json!("0x10")), None);
        assert_eq!(read(json!("12.5")), None);
    }

    #[test]
    fn a_value_of_another_kind_is_not_an_identifier() {
        assert_eq!(read(json!(true)), None);
        assert_eq!(read(json!(1.5)), None);
        assert_eq!(read(json!(null)), None);
        assert_eq!(read(json!([12])), None);
        assert_eq!(read(json!({"id": 12})), None);
        assert_eq!(MessageId::read(None), None);
    }
}
