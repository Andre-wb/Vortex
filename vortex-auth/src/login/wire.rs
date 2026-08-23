use std::fmt;

use crate::challenge::refusal::SecretRefusal;
use crate::login::key::KeyRefusal;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireRefusal {
    Malformed,
    UnknownAccount,
    UnknownSession,
    Key(KeyRefusal),
    Secret(SecretRefusal),
}

impl fmt::Display for WireRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireRefusal::Malformed => write!(f, "запись челленджа входа не разобрана"),
            WireRefusal::UnknownAccount => write!(
                f,
                "запись челленджа входа называет несуществующую учётную запись"
            ),
            WireRefusal::UnknownSession => {
                write!(f, "запись челленджа входа называет неразбираемую QR-сессию")
            }
            WireRefusal::Key(refusal) => write!(f, "{refusal}"),
            WireRefusal::Secret(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for WireRefusal {}
