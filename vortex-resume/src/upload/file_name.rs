use crate::upload::limits;
use crate::upload::refusal::Refusal;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName(String);

impl FileName {
    pub fn parse(value: &str) -> Result<Self, Refusal> {
        if value.is_empty() {
            return Err(Refusal::EmptyFileName);
        }
        if value.chars().count() > limits::MAX_FILE_NAME_LENGTH {
            return Err(Refusal::OverLongFileName);
        }
        if value.chars().any(|c| c.is_control()) {
            return Err(Refusal::FileNameOutsideAlphabet);
        }
        Ok(FileName(value.to_owned()))
    }

    pub fn written(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::FileName;
    use crate::upload::refusal::Refusal;

    #[test]
    fn an_ordinary_name_is_kept_verbatim() {
        assert_eq!(FileName::parse("отчёт.pdf").unwrap().written(), "отчёт.pdf");
    }

    #[test]
    fn an_empty_name_is_refused() {
        assert_eq!(FileName::parse(""), Err(Refusal::EmptyFileName));
    }

    #[test]
    fn a_control_character_is_refused() {
        assert_eq!(
            FileName::parse("report\n.pdf"),
            Err(Refusal::FileNameOutsideAlphabet)
        );
        assert_eq!(
            FileName::parse("report\0.pdf"),
            Err(Refusal::FileNameOutsideAlphabet)
        );
    }

    #[test]
    fn a_name_is_measured_in_characters_not_bytes() {
        assert!(FileName::parse(&"я".repeat(255)).is_ok());
        assert_eq!(
            FileName::parse(&"я".repeat(256)),
            Err(Refusal::OverLongFileName)
        );
    }
}
