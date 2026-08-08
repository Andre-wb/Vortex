pub const CODE_CONNECT: u8 = 0x01;
pub const CODE_UDP_ASSOCIATE: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,
    UdpAssociate,
}

impl Command {
    pub fn parse(code: u8) -> Option<Self> {
        match code {
            CODE_CONNECT => Some(Command::Connect),
            CODE_UDP_ASSOCIATE => Some(Command::UdpAssociate),
            _ => None,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Command::Connect => CODE_CONNECT,
            Command::UdpAssociate => CODE_UDP_ASSOCIATE,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Command::Connect => "connect",
            Command::UdpAssociate => "udp_associate",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, CODE_CONNECT, CODE_UDP_ASSOCIATE};

    #[test]
    fn the_two_commands_of_the_protocol_round_trip() {
        assert_eq!(Command::parse(CODE_CONNECT), Some(Command::Connect));
        assert_eq!(
            Command::parse(CODE_UDP_ASSOCIATE),
            Some(Command::UdpAssociate)
        );
        assert_eq!(Command::Connect.code(), CODE_CONNECT);
        assert_eq!(Command::UdpAssociate.code(), CODE_UDP_ASSOCIATE);
    }

    #[test]
    fn socks_bind_is_not_a_trojan_command() {
        assert_eq!(Command::parse(0x02), None);
        assert_eq!(Command::parse(0x00), None);
        assert_eq!(Command::parse(0xFF), None);
    }

    #[test]
    fn every_command_names_itself() {
        assert_eq!(Command::Connect.name(), "connect");
        assert_eq!(Command::UdpAssociate.name(), "udp_associate");
    }
}
