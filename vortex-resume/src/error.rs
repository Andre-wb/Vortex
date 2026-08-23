use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    Unavailable,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::Unavailable => write!(
                f,
                "общее состояние возобновления недоступно — операция не выполнена"
            ),
        }
    }
}

impl std::error::Error for StateError {}

pub type Result<T> = std::result::Result<T, StateError>;
