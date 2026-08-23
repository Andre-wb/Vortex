#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    Empty,
    TooLong { max: usize, got: usize },
    NotAllowed,
}
