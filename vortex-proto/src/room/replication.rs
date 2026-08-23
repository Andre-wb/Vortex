use crate::room::refusal::RoomRefusal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicationMode {
    None,
    Federated,
}

impl ReplicationMode {
    pub fn read(text: &str) -> Result<Self, RoomRefusal> {
        match text {
            "none" => Ok(ReplicationMode::None),
            "federated" => Ok(ReplicationMode::Federated),
            _ => Err(RoomRefusal::ReplicationMode),
        }
    }

    pub fn shown(stored: Option<&str>) -> String {
        stored
            .filter(|value| !value.is_empty())
            .unwrap_or("none")
            .to_string()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ReplicationMode::None => "none",
            ReplicationMode::Federated => "federated",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReplicationMode;
    use crate::room::refusal::RoomRefusal;

    #[test]
    fn the_two_modes_are_read_and_written_back() {
        for text in ["none", "federated"] {
            assert_eq!(ReplicationMode::read(text).unwrap().as_str(), text);
        }
    }

    #[test]
    fn anything_else_is_not_a_mode() {
        for text in ["", "None", "local", "federate"] {
            assert_eq!(
                ReplicationMode::read(text),
                Err(RoomRefusal::ReplicationMode)
            );
        }
    }

    #[test]
    fn a_room_that_never_chose_replicates_nowhere() {
        assert_eq!(ReplicationMode::shown(None), "none");
        assert_eq!(ReplicationMode::shown(Some("")), "none");
        assert_eq!(ReplicationMode::shown(Some("federated")), "federated");
    }
}
