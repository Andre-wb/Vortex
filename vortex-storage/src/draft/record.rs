use crate::time::stamp::Stamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftRecord {
    pub user_id: i64,
    pub room_id: i64,
    pub text: String,
    pub updated_at: Stamp,
}

#[cfg(test)]
mod tests {
    use super::DraftRecord;
    use crate::time::stamp::Stamp;

    fn draft(room_id: i64) -> DraftRecord {
        DraftRecord {
            user_id: 7,
            room_id,
            text: "неотправленное".to_owned(),
            updated_at: Stamp::from_unix(1_785_834_930, 0).unwrap(),
        }
    }

    #[test]
    fn a_draft_belongs_to_one_account_in_one_room() {
        assert_eq!((draft(1).user_id, draft(1).room_id), (7, 1));
    }

    #[test]
    fn one_account_drafting_in_two_rooms_has_two_drafts() {
        assert_ne!(draft(1), draft(2));
    }
}
