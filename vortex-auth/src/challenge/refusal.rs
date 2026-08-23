use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRefusal {
    TooShort { min: usize, got: usize },
    TooLong { max: usize, got: usize },
    NotHex,
}

impl fmt::Display for SecretRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRefusal::TooShort { min, got } => {
                write!(f, "секрет челленджа короче {min} байт, получено {got}")
            }
            SecretRefusal::TooLong { max, got } => {
                write!(f, "секрет челленджа длиннее {max} байт, получено {got}")
            }
            SecretRefusal::NotHex => write!(f, "секрет челленджа записан не шестнадцатерично"),
        }
    }
}

impl std::error::Error for SecretRefusal {}
