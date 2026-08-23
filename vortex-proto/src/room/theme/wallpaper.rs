use crate::room::refusal::RoomRefusal;

pub const PRESETS: [&str; 7] = [
    "none",
    "stars",
    "aurora",
    "sunset",
    "ocean-wave",
    "mesh",
    "deep-space",
];

pub const CUSTOM_PREFIX: &str = "https://";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wallpaper(String);

impl Wallpaper {
    pub fn read(text: &str) -> Result<Self, RoomRefusal> {
        if PRESETS.contains(&text) || text.starts_with(CUSTOM_PREFIX) {
            return Ok(Wallpaper(text.to_string()));
        }
        Err(RoomRefusal::Wallpaper(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Wallpaper, PRESETS};
    use crate::room::refusal::RoomRefusal;

    #[test]
    fn every_preset_is_accepted_by_its_name() {
        for preset in PRESETS {
            assert_eq!(Wallpaper::read(preset).unwrap().as_str(), preset);
        }
    }

    #[test]
    fn a_wallpaper_of_ones_own_is_accepted_only_over_https() {
        assert!(Wallpaper::read("https://example.org/a.png").is_ok());
        assert_eq!(
            Wallpaper::read("http://example.org/a.png"),
            Err(RoomRefusal::Wallpaper(
                "http://example.org/a.png".to_string()
            ))
        );
    }

    #[test]
    fn an_unknown_name_is_refused_and_named_in_the_refusal() {
        assert_eq!(
            Wallpaper::read("moon").unwrap_err().detail(),
            "Invalid wallpaper: moon"
        );
    }

    #[test]
    fn an_empty_wallpaper_is_not_a_wallpaper() {
        assert!(Wallpaper::read("").is_err());
    }
}
