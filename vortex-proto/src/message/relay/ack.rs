use crate::message::time::wire_stamp::wire_stamp;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    pub client_msg_id: String,
    pub server_id: Option<i64>,
    pub created_at: Option<String>,
    pub duplicate: bool,
}

impl Ack {
    pub fn stored(client_msg_id: &str, server_id: i64, created_at: i64) -> Self {
        Ack {
            client_msg_id: client_msg_id.to_string(),
            server_id: Some(server_id),
            created_at: Some(wire_stamp(created_at)),
            duplicate: false,
        }
    }

    pub fn duplicate(client_msg_id: &str) -> Self {
        Ack {
            client_msg_id: client_msg_id.to_string(),
            server_id: None,
            created_at: None,
            duplicate: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Ack;

    #[test]
    fn a_stored_message_is_acknowledged_with_its_server_identifier() {
        let ack = Ack::stored("c-1", 42, 1_785_834_930);
        assert_eq!(ack.client_msg_id, "c-1");
        assert_eq!(ack.server_id, Some(42));
        assert_eq!(ack.created_at.as_deref(), Some("2026-08-04T09:15:30Z"));
        assert!(!ack.duplicate);
    }

    #[test]
    fn a_repeat_is_acknowledged_without_storing_anything() {
        let ack = Ack::duplicate("c-1");
        assert!(ack.duplicate);
        assert_eq!(ack.server_id, None);
        assert_eq!(ack.created_at, None);
    }
}
