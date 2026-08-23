use crate::room::refusal::RoomRefusal;
use crate::room::theme::accent::Accent;
use crate::room::theme::wallpaper::Wallpaper;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Theme {
    pub wallpaper: Option<Wallpaper>,
    pub accent: Option<Accent>,
    pub dark_mode: Option<bool>,
}

impl Theme {
    pub fn read(
        wallpaper: Option<&str>,
        accent: Option<&str>,
        dark_mode: Option<bool>,
    ) -> Result<Self, RoomRefusal> {
        Ok(Theme {
            wallpaper: wallpaper.map(Wallpaper::read).transpose()?,
            accent: accent.map(Accent::read).transpose()?,
            dark_mode,
        })
    }

    pub fn written(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(wallpaper) = &self.wallpaper {
            parts.push(format!(
                "\"wallpaper\":{}",
                serde_json::Value::from(wallpaper.as_str())
            ));
        }
        if let Some(accent) = &self.accent {
            parts.push(format!("\"accent\":\"{}\"", accent.as_str()));
        }
        if let Some(dark_mode) = self.dark_mode {
            parts.push(format!("\"dark_mode\":{dark_mode}"));
        }
        format!("{{{}}}", parts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::Theme;
    use crate::room::refusal::RoomRefusal;

    #[test]
    fn a_full_theme_is_written_in_the_order_it_is_read() {
        let theme = Theme::read(Some("stars"), Some("#1a2b3c"), Some(true)).unwrap();
        assert_eq!(
            theme.written(),
            r##"{"wallpaper":"stars","accent":"#1a2b3c","dark_mode":true}"##
        );
    }

    #[test]
    fn a_theme_that_sets_nothing_is_written_as_an_empty_object() {
        assert_eq!(Theme::read(None, None, None).unwrap().written(), "{}");
    }

    #[test]
    fn only_what_was_set_is_written() {
        assert_eq!(
            Theme::read(None, None, Some(false)).unwrap().written(),
            r#"{"dark_mode":false}"#
        );
        assert_eq!(
            Theme::read(Some("none"), None, None).unwrap().written(),
            r#"{"wallpaper":"none"}"#
        );
    }

    #[test]
    fn a_wallpaper_of_ones_own_is_escaped_the_way_json_escapes_it() {
        let theme = Theme::read(Some("https://example.org/a\"b.png"), None, None).unwrap();
        assert_eq!(
            theme.written(),
            r#"{"wallpaper":"https://example.org/a\"b.png"}"#
        );
    }

    #[test]
    fn a_theme_is_refused_by_whichever_field_is_wrong() {
        assert_eq!(
            Theme::read(Some("moon"), None, None),
            Err(RoomRefusal::Wallpaper("moon".to_string()))
        );
        assert_eq!(
            Theme::read(Some("stars"), Some("red"), None),
            Err(RoomRefusal::Accent)
        );
    }

    #[test]
    fn the_wallpaper_is_checked_before_the_accent() {
        assert_eq!(
            Theme::read(Some("moon"), Some("red"), None),
            Err(RoomRefusal::Wallpaper("moon".to_string()))
        );
    }
}
