use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    NotHex,
    Length { expected: usize, got: usize },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HexError::NotHex => write!(f, "значение не шестнадцатеричное"),
            HexError::Length { expected, got } => {
                write!(f, "ожидалось {expected} байт, получено {got}")
            }
        }
    }
}

impl std::error::Error for HexError {}
