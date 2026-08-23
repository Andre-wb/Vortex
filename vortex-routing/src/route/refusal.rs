use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteNameRefusal {
    Empty,
    TooLong,
    Alphabet,
}

impl fmt::Display for RouteNameRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteNameRefusal::Empty => write!(f, "имя роута пустое"),
            RouteNameRefusal::TooLong => write!(f, "имя роута длиннее допустимого"),
            RouteNameRefusal::Alphabet => {
                write!(f, "имя роута содержит символы вне [a-z0-9-]")
            }
        }
    }
}

impl std::error::Error for RouteNameRefusal {}
