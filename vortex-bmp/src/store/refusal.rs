#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositRefusal {
    TooLarge,
    AtCapacity,
}
