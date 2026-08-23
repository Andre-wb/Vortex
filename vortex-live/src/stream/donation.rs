use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::identity::person::Person;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Donation {
    pub user_id: i64,
    pub username: String,
    pub display_name: String,
    pub avatar_emoji: String,
    pub amount: String,
    pub currency: String,
    pub message: String,
    pub timestamp: String,
}

impl Donation {
    pub fn from(person: &Person, amount: &str, currency: &str, message: &str, at: String) -> Self {
        Donation {
            user_id: person.user_id,
            username: person.username.clone(),
            display_name: person.display_name.clone(),
            avatar_emoji: person.avatar_emoji.clone(),
            amount: amount.to_owned(),
            currency: currency.to_owned(),
            message: message.to_owned(),
            timestamp: at,
        }
    }

    pub fn view(&self) -> Value {
        json!({
            "user_id": self.user_id,
            "username": self.username,
            "display_name": self.display_name,
            "avatar_emoji": self.avatar_emoji,
            "amount": self.amount,
            "currency": self.currency,
            "message": self.message,
            "timestamp": self.timestamp,
        })
    }

    pub fn to_wire(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn parse(wire: &str) -> Option<Self> {
        serde_json::from_str(wire).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::Donation;
    use crate::identity::person::Person;

    fn donation() -> Donation {
        Donation::from(
            &Person::of(7, "ann", Some("Ann"), None, None),
            "500",
            "RUB",
            "спасибо",
            "2026-08-04T09:15:30+00:00".to_owned(),
        )
    }

    #[test]
    fn a_donation_carries_who_sent_it_and_what_they_wrote() {
        let view = donation().view();
        assert_eq!(view["user_id"], 7);
        assert_eq!(view["display_name"], "Ann");
        assert_eq!(view["amount"], "500");
        assert_eq!(view["currency"], "RUB");
        assert_eq!(view["message"], "спасибо");
    }

    #[test]
    fn a_donation_survives_the_trip_through_the_store() {
        assert_eq!(Donation::parse(&donation().to_wire()).unwrap(), donation());
    }

    #[test]
    fn what_the_store_could_not_have_written_is_not_a_donation() {
        assert!(Donation::parse("").is_none());
        assert!(Donation::parse("{\"amount\": \"500\"}").is_none());
    }
}
