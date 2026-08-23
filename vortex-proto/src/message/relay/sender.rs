#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sender {
    pub user_id: Option<i64>,
    pub pseudo: Option<String>,
    pub username: String,
    pub display_name: String,
    pub avatar_emoji: Option<String>,
    pub avatar_url: Option<String>,
    pub is_bot: bool,
    pub tag: Option<String>,
    pub tag_color: Option<String>,
    pub reply_color: Option<String>,
    pub reply_icon: Option<String>,
}

impl Sender {
    pub fn named(username: &str, display_name: Option<&str>) -> Self {
        Sender {
            username: username.to_string(),
            display_name: shown(username, display_name),
            ..Sender::default()
        }
    }

    pub fn shown_name(&self) -> &str {
        &self.display_name
    }
}

fn shown(username: &str, display_name: Option<&str>) -> String {
    display_name
        .filter(|name| !name.is_empty())
        .unwrap_or(username)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::Sender;

    #[test]
    fn a_sender_without_a_display_name_is_shown_by_its_username() {
        assert_eq!(Sender::named("alice", None).shown_name(), "alice");
        assert_eq!(Sender::named("alice", Some("")).shown_name(), "alice");
    }

    #[test]
    fn a_display_name_is_shown_when_there_is_one() {
        assert_eq!(
            Sender::named("alice", Some("Alice A.")).shown_name(),
            "Alice A."
        );
    }

    #[test]
    fn a_plain_sender_is_nobody_in_particular() {
        let sender = Sender::named("alice", None);
        assert_eq!(sender.user_id, None);
        assert_eq!(sender.pseudo, None);
        assert!(!sender.is_bot);
        assert_eq!(sender.tag, None);
    }
}
