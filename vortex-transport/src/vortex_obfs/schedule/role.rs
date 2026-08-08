pub const DATA_INITIATOR_LABEL: &[u8] = b"vortex-obfs data i2r v2";
pub const DATA_RESPONDER_LABEL: &[u8] = b"vortex-obfs data r2i v2";
pub const LENGTH_INITIATOR_LABEL: &[u8] = b"vortex-obfs len i2r v2";
pub const LENGTH_RESPONDER_LABEL: &[u8] = b"vortex-obfs len r2i v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    pub fn peer(&self) -> Role {
        match self {
            Role::Initiator => Role::Responder,
            Role::Responder => Role::Initiator,
        }
    }

    pub fn send_data_label(&self) -> &'static [u8] {
        match self {
            Role::Initiator => DATA_INITIATOR_LABEL,
            Role::Responder => DATA_RESPONDER_LABEL,
        }
    }

    pub fn recv_data_label(&self) -> &'static [u8] {
        self.peer().send_data_label()
    }

    pub fn send_length_label(&self) -> &'static [u8] {
        match self {
            Role::Initiator => LENGTH_INITIATOR_LABEL,
            Role::Responder => LENGTH_RESPONDER_LABEL,
        }
    }

    pub fn recv_length_label(&self) -> &'static [u8] {
        self.peer().send_length_label()
    }
}

#[cfg(test)]
mod tests {
    use super::Role;

    #[test]
    fn each_side_sends_what_the_other_side_expects_to_receive() {
        assert_eq!(
            Role::Initiator.send_data_label(),
            Role::Responder.recv_data_label()
        );
        assert_eq!(
            Role::Responder.send_data_label(),
            Role::Initiator.recv_data_label()
        );
        assert_eq!(
            Role::Initiator.send_length_label(),
            Role::Responder.recv_length_label()
        );
    }

    #[test]
    fn the_two_directions_never_share_a_label() {
        assert_ne!(
            Role::Initiator.send_data_label(),
            Role::Responder.send_data_label()
        );
    }

    #[test]
    fn the_data_and_the_length_never_share_a_label() {
        assert_ne!(
            Role::Initiator.send_data_label(),
            Role::Initiator.send_length_label()
        );
        assert_ne!(
            Role::Responder.send_data_label(),
            Role::Responder.send_length_label()
        );
    }

    #[test]
    fn the_peer_of_the_peer_is_oneself() {
        assert_eq!(Role::Initiator.peer().peer(), Role::Initiator);
        assert_eq!(Role::Responder.peer(), Role::Initiator);
    }
}
