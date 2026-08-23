use serde_json::Value;

use crate::stream::participant::StreamParticipant;

pub fn raised(queue: &[i64], seated: &[StreamParticipant]) -> Vec<Value> {
    queue
        .iter()
        .filter_map(|user_id| {
            seated
                .iter()
                .find(|participant| participant.person.user_id == *user_id)
                .filter(|participant| participant.hand_raised)
                .map(StreamParticipant::view)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::raised;
    use crate::stream::participant::tests::{host, viewer};

    #[test]
    fn the_queue_is_shown_in_the_order_hands_went_up() {
        let seated = vec![host().with_hand(true), viewer().with_hand(true)];
        let shown = raised(&[8, 7], &seated);
        assert_eq!(shown.len(), 2);
        assert_eq!(shown[0]["user_id"], 8);
        assert_eq!(shown[1]["user_id"], 7);
    }

    #[test]
    fn a_hand_that_went_down_is_not_shown_even_while_the_queue_remembers_it() {
        let shown = raised(&[8], &[viewer()]);
        assert!(shown.is_empty());
    }

    #[test]
    fn a_queue_naming_somebody_who_left_shows_nobody() {
        let shown = raised(&[9], &[viewer().with_hand(true)]);
        assert!(shown.is_empty());
    }
}
