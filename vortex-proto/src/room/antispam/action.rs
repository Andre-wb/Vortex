#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AntispamAction {
    Warn,
    Mute,
    Kick,
    Ban,
}

impl AntispamAction {
    pub fn read(text: &str) -> Option<Self> {
        match text {
            "warn" => Some(AntispamAction::Warn),
            "mute" => Some(AntispamAction::Mute),
            "kick" => Some(AntispamAction::Kick),
            "ban" => Some(AntispamAction::Ban),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AntispamAction::Warn => "warn",
            AntispamAction::Mute => "mute",
            AntispamAction::Kick => "kick",
            AntispamAction::Ban => "ban",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AntispamAction;

    #[test]
    fn the_four_answers_to_spam_are_read_and_written_back() {
        for text in ["warn", "mute", "kick", "ban"] {
            assert_eq!(AntispamAction::read(text).unwrap().as_str(), text);
        }
    }

    #[test]
    fn anything_else_is_not_an_answer() {
        for text in ["", "WARN", "delete", "warn "] {
            assert_eq!(AntispamAction::read(text), None);
        }
    }
}
