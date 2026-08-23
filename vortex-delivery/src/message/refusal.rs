use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Empty,
    TooLong,
    Unprintable,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Empty => write!(f, "идентификатор сообщения пуст"),
            Refusal::TooLong => write!(f, "идентификатор сообщения длиннее 128 знаков"),
            Refusal::Unprintable => write!(
                f,
                "идентификатор сообщения содержит знак вне [A-Za-z0-9_.:-]"
            ),
        }
    }
}

impl std::error::Error for Refusal {}
