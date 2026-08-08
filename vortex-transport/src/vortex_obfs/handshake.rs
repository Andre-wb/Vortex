use crate::vortex_obfs::schedule::salt::SessionSalt;
use crate::vortex_obfs::session::Session;

pub struct Handshake {
    pub salt: SessionSalt,
    pub session: Session,
}

impl Handshake {
    pub fn new(salt: SessionSalt, session: Session) -> Self {
        Handshake { salt, session }
    }

    pub fn prologue(&self) -> &[u8] {
        self.salt.as_bytes()
    }
}
