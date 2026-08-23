use serde::{Deserialize, Serialize};

pub const DEFAULT_AVATAR: &str = "\u{1f464}";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Person {
    pub user_id: i64,
    pub username: String,
    pub display_name: String,
    pub avatar_emoji: String,
    pub avatar_url: Option<String>,
}

impl Person {
    pub fn of(
        user_id: i64,
        username: &str,
        display_name: Option<&str>,
        avatar_emoji: Option<&str>,
        avatar_url: Option<&str>,
    ) -> Self {
        Person {
            user_id,
            username: username.to_owned(),
            display_name: named(display_name, username),
            avatar_emoji: named(avatar_emoji, DEFAULT_AVATAR),
            avatar_url: avatar_url
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
        }
    }
}

fn named(given: Option<&str>, fallback: &str) -> String {
    given
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Person, DEFAULT_AVATAR};

    #[test]
    fn a_person_without_a_display_name_is_shown_by_username() {
        let person = Person::of(7, "ann", None, None, None);
        assert_eq!(person.display_name, "ann");
        assert_eq!(person.avatar_emoji, DEFAULT_AVATAR);
        assert_eq!(person.avatar_url, None);
    }

    #[test]
    fn an_empty_display_name_is_the_same_as_none() {
        assert_eq!(
            Person::of(7, "ann", Some(""), Some(""), Some("")).display_name,
            "ann"
        );
        assert_eq!(
            Person::of(7, "ann", Some(""), Some(""), Some("")).avatar_emoji,
            DEFAULT_AVATAR
        );
        assert_eq!(Person::of(7, "ann", None, None, Some("")).avatar_url, None);
    }

    #[test]
    fn what_the_account_carries_is_kept_as_it_is() {
        let person = Person::of(
            7,
            "ann",
            Some("Ann"),
            Some("\u{1f680}"),
            Some("https://a.invalid/a.png"),
        );
        assert_eq!(person.display_name, "Ann");
        assert_eq!(person.avatar_emoji, "\u{1f680}");
        assert_eq!(
            person.avatar_url.as_deref(),
            Some("https://a.invalid/a.png")
        );
    }
}
