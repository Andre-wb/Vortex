use crate::shadowtls::switch::session_id::SessionId;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientStep {
    pub forward: Vec<u8>,
    pub switch: Option<SessionId>,
    pub trailing: Vec<u8>,
    pub opaque: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DonorStep {
    pub forward: Vec<u8>,
    pub opaque: bool,
}
