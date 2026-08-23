use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncVersion(u8);

impl EncVersion {
    pub fn read(value: Option<&Value>) -> Option<Self> {
        match value? {
            Value::Number(number) => number
                .as_u64()
                .filter(|version| *version <= u8::MAX as u64)
                .map(|version| EncVersion(version as u8)),
            _ => None,
        }
    }

    pub fn value(&self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::EncVersion;
    use serde_json::json;

    fn read(value: serde_json::Value) -> Option<u8> {
        EncVersion::read(Some(&value)).map(|version| version.value())
    }

    #[test]
    fn a_small_whole_number_is_a_version() {
        assert_eq!(read(json!(0)), Some(0));
        assert_eq!(read(json!(1)), Some(1));
        assert_eq!(read(json!(7)), Some(7));
        assert_eq!(read(json!(255)), Some(255));
    }

    #[test]
    fn a_number_outside_the_byte_is_not_a_version() {
        assert_eq!(read(json!(256)), None);
        assert_eq!(read(json!(-1)), None);
    }

    #[test]
    fn a_value_that_is_not_a_whole_number_is_not_a_version() {
        assert_eq!(read(json!("1")), None);
        assert_eq!(read(json!(1.5)), None);
        assert_eq!(read(json!(true)), None);
        assert_eq!(read(json!(false)), None);
        assert_eq!(read(json!([1])), None);
        assert_eq!(read(json!({"v": 1})), None);
        assert_eq!(read(json!(null)), None);
    }

    #[test]
    fn an_absent_field_is_a_pre_versioning_envelope() {
        assert_eq!(EncVersion::read(None), None);
    }
}
