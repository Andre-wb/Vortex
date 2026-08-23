#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoomRefusal {
    Name,
    Description,
    Avatar,
    AllowedReactions,
    ReactionsType,
    ReplicationMode,
    Wallpaper(String),
    Accent,
}

impl RoomRefusal {
    pub fn detail(&self) -> String {
        match self {
            RoomRefusal::Name => "Invalid room name".to_string(),
            RoomRefusal::Description => "Invalid room description".to_string(),
            RoomRefusal::Avatar => "Invalid room avatar".to_string(),
            RoomRefusal::AllowedReactions => "Invalid allowed_reactions".to_string(),
            RoomRefusal::ReactionsType => "Invalid reactions_type".to_string(),
            RoomRefusal::ReplicationMode => "Invalid replication mode".to_string(),
            RoomRefusal::Wallpaper(value) => format!("Invalid wallpaper: {value}"),
            RoomRefusal::Accent => "Invalid accent".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RoomRefusal;

    #[test]
    fn every_refusal_says_something() {
        for refusal in [
            RoomRefusal::Name,
            RoomRefusal::Description,
            RoomRefusal::Avatar,
            RoomRefusal::AllowedReactions,
            RoomRefusal::ReactionsType,
            RoomRefusal::ReplicationMode,
            RoomRefusal::Accent,
        ] {
            assert!(!refusal.detail().is_empty());
        }
    }

    #[test]
    fn a_refused_wallpaper_is_named_in_the_refusal() {
        assert_eq!(
            RoomRefusal::Wallpaper("moon".to_string()).detail(),
            "Invalid wallpaper: moon"
        );
    }
}
