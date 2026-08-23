use crate::time::stamp::Stamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRecord {
    pub bot_id: i64,
    pub url: String,
    pub secret: String,
    pub events: String,
    pub created_at: Stamp,
}

#[cfg(test)]
mod tests {
    use super::WebhookRecord;
    use crate::time::stamp::Stamp;

    fn record(url: &str) -> WebhookRecord {
        WebhookRecord {
            bot_id: 7,
            url: url.to_owned(),
            secret: "s3cret".to_owned(),
            events: "[\"message\"]".to_owned(),
            created_at: Stamp::from_unix(1_785_834_930, 0).unwrap(),
        }
    }

    #[test]
    fn a_webhook_carries_the_bot_it_belongs_to() {
        assert_eq!(record("https://example.test/hook").bot_id, 7);
    }

    #[test]
    fn two_webhooks_differing_in_address_are_two_records() {
        assert_ne!(record("https://a.test/hook"), record("https://b.test/hook"));
    }
}
