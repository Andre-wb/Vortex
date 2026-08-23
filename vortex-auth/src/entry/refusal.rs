use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressRefusal {
    Empty,
    TooLong { max: usize, got: usize },
    NotPrintable,
}

impl fmt::Display for AddressRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressRefusal::Empty => write!(f, "адрес клиента пуст"),
            AddressRefusal::TooLong { max, got } => {
                write!(f, "адрес клиента длиннее {max} символов, получено {got}")
            }
            AddressRefusal::NotPrintable => {
                write!(f, "адрес клиента содержит непечатаемый символ")
            }
        }
    }
}

impl std::error::Error for AddressRefusal {}

#[cfg(test)]
mod tests {
    use super::AddressRefusal;

    #[test]
    fn a_refusal_says_what_is_wrong_with_the_address() {
        assert_eq!(AddressRefusal::Empty.to_string(), "адрес клиента пуст");
        assert_eq!(
            AddressRefusal::TooLong { max: 64, got: 65 }.to_string(),
            "адрес клиента длиннее 64 символов, получено 65"
        );
        assert_eq!(
            AddressRefusal::NotPrintable.to_string(),
            "адрес клиента содержит непечатаемый символ"
        );
    }
}
