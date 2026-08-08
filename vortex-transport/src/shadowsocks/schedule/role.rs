pub const DATA_CLIENT_LABEL: &[u8] = b"vortex-shadowsocks data c2s v2";
pub const DATA_SERVER_LABEL: &[u8] = b"vortex-shadowsocks data s2c v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub fn peer(&self) -> Role {
        match self {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        }
    }

    pub fn send_label(&self) -> &'static [u8] {
        match self {
            Role::Client => DATA_CLIENT_LABEL,
            Role::Server => DATA_SERVER_LABEL,
        }
    }

    pub fn recv_label(&self) -> &'static [u8] {
        self.peer().send_label()
    }
}

#[cfg(test)]
mod tests {
    use super::Role;

    #[test]
    fn each_side_sends_what_the_other_side_expects_to_receive() {
        assert_eq!(Role::Client.send_label(), Role::Server.recv_label());
        assert_eq!(Role::Server.send_label(), Role::Client.recv_label());
    }

    #[test]
    fn the_two_directions_never_share_a_label() {
        assert_ne!(Role::Client.send_label(), Role::Server.send_label());
    }

    #[test]
    fn the_peer_of_the_peer_is_oneself() {
        assert_eq!(Role::Client.peer().peer(), Role::Client);
        assert_eq!(Role::Server.peer(), Role::Client);
    }
}
