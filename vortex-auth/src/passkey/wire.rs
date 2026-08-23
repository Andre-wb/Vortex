use std::fmt;

use crate::challenge::refusal::SecretRefusal;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireRefusal {
    Malformed,
    UnknownAccount,
    Secret(SecretRefusal),
}

impl fmt::Display for WireRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireRefusal::Malformed => write!(f, "запись челленджа passkey не разобрана"),
            WireRefusal::UnknownAccount => {
                write!(
                    f,
                    "запись челленджа passkey называет несуществующую учётную запись"
                )
            }
            WireRefusal::Secret(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for WireRefusal {}
