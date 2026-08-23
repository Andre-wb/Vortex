use time::PrimitiveDateTime;

use crate::bot::webhook::record::WebhookRecord;
use crate::time::stamp::Stamp;

pub struct WebhookRow {
    pub bot_id: i32,
    pub url: String,
    pub secret: String,
    pub events: Option<String>,
    pub created_at: Option<PrimitiveDateTime>,
}

impl WebhookRow {
    pub fn into_record(self, fallback: Stamp) -> WebhookRecord {
        WebhookRecord {
            bot_id: i64::from(self.bot_id),
            url: self.url,
            secret: self.secret,
            events: self.events.unwrap_or_else(|| "[]".to_owned()),
            created_at: self.created_at.map(Stamp::from_reading).unwrap_or(fallback),
        }
    }
}
