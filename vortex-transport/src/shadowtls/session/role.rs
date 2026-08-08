#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

pub const INFO_CLIENT_TO_SERVER: &[u8] = b"shadowtls c2s v2";
pub const INFO_SERVER_TO_CLIENT: &[u8] = b"shadowtls s2c v2";

impl Direction {
    pub fn info(&self) -> &'static [u8] {
        match self {
            Direction::ClientToServer => INFO_CLIENT_TO_SERVER,
            Direction::ServerToClient => INFO_SERVER_TO_CLIENT,
        }
    }
}

impl Role {
    pub fn sending(&self) -> Direction {
        match self {
            Role::Server => Direction::ServerToClient,
            Role::Client => Direction::ClientToServer,
        }
    }

    pub fn receiving(&self) -> Direction {
        match self {
            Role::Server => Direction::ClientToServer,
            Role::Client => Direction::ServerToClient,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Direction, Role};

    #[test]
    fn the_two_sides_mirror_each_other() {
        assert_eq!(Role::Server.sending(), Role::Client.receiving());
        assert_eq!(Role::Server.receiving(), Role::Client.sending());
    }

    #[test]
    fn the_directions_carry_different_labels() {
        assert_ne!(
            Direction::ClientToServer.info(),
            Direction::ServerToClient.info()
        );
    }
}
