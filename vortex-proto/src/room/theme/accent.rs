use crate::room::refusal::RoomRefusal;

pub const ACCENT_LEN: usize = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accent(String);

impl Accent {
    pub fn read(text: &str) -> Result<Self, RoomRefusal> {
        let bytes = text.as_bytes();
        if bytes.len() != ACCENT_LEN
            || bytes[0] != b'#'
            || !bytes[1..].iter().all(u8::is_ascii_hexdigit)
        {
            return Err(RoomRefusal::Accent);
        }
        Ok(Accent(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Accent;
    use crate::room::refusal::RoomRefusal;

    #[test]
    fn a_six_digit_colour_is_kept_exactly_as_written() {
        assert_eq!(Accent::read("#1a2B3c").unwrap().as_str(), "#1a2B3c");
        assert_eq!(Accent::read("#000000").unwrap().as_str(), "#000000");
    }

    #[test]
    fn a_colour_of_another_shape_is_refused() {
        for text in [
            "",
            "#fff",
            "1a2b3c",
            "#1a2b3",
            "#1a2b3cd",
            "#12345g",
            "＃1a2b3c",
        ] {
            assert_eq!(Accent::read(text), Err(RoomRefusal::Accent), "{text}");
        }
    }
}
