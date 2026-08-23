#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeletedMessage {
    pub msg_id: i64,
}

impl DeletedMessage {
    pub fn render(msg_id: i64) -> Self {
        DeletedMessage { msg_id }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadUpdate {
    pub msg_id: i64,
    pub thread_count: i64,
}

impl ThreadUpdate {
    pub fn render(msg_id: i64, thread_count: Option<i64>) -> Self {
        ThreadUpdate {
            msg_id,
            thread_count: thread_count.unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeletedMessage, ThreadUpdate};

    #[test]
    fn a_deletion_names_only_the_message_that_went_away() {
        assert_eq!(DeletedMessage::render(9).msg_id, 9);
    }

    #[test]
    fn a_thread_without_a_counter_is_reported_as_empty() {
        assert_eq!(ThreadUpdate::render(42, None).thread_count, 0);
        assert_eq!(ThreadUpdate::render(42, Some(3)).thread_count, 3);
    }
}
