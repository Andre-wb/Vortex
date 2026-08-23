use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireRefusal {
    Malformed,
    UnknownAccount,
    UnknownChallenge,
}

impl fmt::Display for WireRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireRefusal::Malformed => write!(f, "запись QR-сессии не разобрана"),
            WireRefusal::UnknownAccount => {
                write!(f, "запись QR-сессии называет несуществующую учётную запись")
            }
            WireRefusal::UnknownChallenge => {
                write!(f, "запись QR-сессии называет неразбираемый челлендж")
            }
        }
    }
}

impl std::error::Error for WireRefusal {}
