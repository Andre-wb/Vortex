use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BmpError {
    MailboxIdLength { min: usize, max: usize, got: usize },
    MailboxIdNotHex,
    SecretNotHex,
    SecretLength { expected: usize, got: usize },
}

impl fmt::Display for BmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BmpError::MailboxIdLength { min, max, got } => write!(
                f,
                "длина идентификатора ящика должна быть от {min} до {max}, получено {got}"
            ),
            BmpError::MailboxIdNotHex => {
                write!(f, "идентификатор ящика не шестнадцатеричный")
            }
            BmpError::SecretNotHex => write!(f, "секрет комнаты не шестнадцатеричный"),
            BmpError::SecretLength { expected, got } => write!(
                f,
                "секрет комнаты должен быть длиной {expected} байт, получено {got}"
            ),
        }
    }
}

impl std::error::Error for BmpError {}

pub type Result<T> = std::result::Result<T, BmpError>;
