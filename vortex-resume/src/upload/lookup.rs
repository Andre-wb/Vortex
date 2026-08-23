use crate::upload::progress::Progress;
use crate::upload::session::Session;

#[derive(Debug, Clone, PartialEq)]
pub enum Found {
    Live(Box<Session>),
    Expired,
    Missing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Reception {
    Accepted(Progress),
    AlreadyHeld(Progress),
    OutsidePlan { total: u32 },
    Expired,
    Missing,
}
