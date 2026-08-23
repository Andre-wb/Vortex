use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CountError {
    Unavailable,
}

impl fmt::Display for CountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CountError::Unavailable => write!(
                f,
                "общий счёт попыток недоступен — попытку некому сосчитать"
            ),
        }
    }
}

impl std::error::Error for CountError {}

pub type Result<T> = std::result::Result<T, CountError>;
