use crate::voice::participant::Participant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Joined {
    Fresh(Participant),
    Already(Participant),
}

impl Joined {
    pub fn already_in(&self) -> bool {
        matches!(self, Joined::Already(_))
    }

    pub fn participant(&self) -> &Participant {
        match self {
            Joined::Fresh(participant) | Joined::Already(participant) => participant,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Joined;
    use crate::voice::participant::Participant;

    fn participant() -> Participant {
        Participant {
            user_id: 7,
            username: "ann".to_owned(),
            display_name: "Ann".to_owned(),
            avatar_emoji: "\u{1f464}".to_owned(),
            avatar_url: None,
            joined_at: "2026-08-04T09:15:30+00:00".to_owned(),
            is_muted: false,
            is_video: false,
        }
    }

    #[test]
    fn a_first_join_is_not_a_repeat() {
        let joined = Joined::Fresh(participant());
        assert!(!joined.already_in());
        assert_eq!(joined.participant(), &participant());
    }

    #[test]
    fn a_repeat_join_gives_back_who_is_already_there() {
        let joined = Joined::Already(participant());
        assert!(joined.already_in());
        assert_eq!(joined.participant(), &participant());
    }
}
