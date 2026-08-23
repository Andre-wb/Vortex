use crate::room::refusal::RoomRefusal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReactionsType {
    All,
    Selected,
    Off,
}

impl ReactionsType {
    pub fn read(text: &str) -> Result<Self, RoomRefusal> {
        match text {
            "all" => Ok(ReactionsType::All),
            "selected" => Ok(ReactionsType::Selected),
            "off" => Ok(ReactionsType::Off),
            _ => Err(RoomRefusal::ReactionsType),
        }
    }

    pub fn shown(stored: Option<&str>) -> String {
        stored
            .filter(|value| !value.is_empty())
            .unwrap_or("all")
            .to_string()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ReactionsType::All => "all",
            ReactionsType::Selected => "selected",
            ReactionsType::Off => "off",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReactionsType;
    use crate::room::refusal::RoomRefusal;

    #[test]
    fn the_three_settings_are_read_and_written_back() {
        for text in ["all", "selected", "off"] {
            assert_eq!(ReactionsType::read(text).unwrap().as_str(), text);
        }
    }

    #[test]
    fn anything_else_is_not_a_setting() {
        for text in ["", "ALL", "none", "some"] {
            assert_eq!(ReactionsType::read(text), Err(RoomRefusal::ReactionsType));
        }
    }

    #[test]
    fn a_room_that_never_chose_shows_every_reaction() {
        assert_eq!(ReactionsType::shown(None), "all");
        assert_eq!(ReactionsType::shown(Some("")), "all");
        assert_eq!(ReactionsType::shown(Some("off")), "off");
    }
}
