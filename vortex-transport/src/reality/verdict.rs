use crate::reality::short_id::value::ShortId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    NotAClientHello,
    NoSessionId,
    NoKeyShare,
    Undecryptable,
    UnsupportedVersion,
    OutsideTimeWindow,
    UnknownShortId,
    Replayed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthVerdict {
    Authenticated(ShortId),
    Rejected(RejectReason),
}

impl AuthVerdict {
    pub fn is_authenticated(&self) -> bool {
        matches!(self, AuthVerdict::Authenticated(_))
    }

    pub fn short_id(&self) -> Option<&ShortId> {
        match self {
            AuthVerdict::Authenticated(short_id) => Some(short_id),
            AuthVerdict::Rejected(_) => None,
        }
    }

    pub fn reason(&self) -> Option<RejectReason> {
        match self {
            AuthVerdict::Authenticated(_) => None,
            AuthVerdict::Rejected(reason) => Some(*reason),
        }
    }
}
