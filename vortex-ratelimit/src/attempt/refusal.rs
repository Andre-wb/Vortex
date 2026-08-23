use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberRefusal {
    Empty,
    TooLong { max: usize, got: usize },
    NotPrintable,
}

impl fmt::Display for MemberRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemberRefusal::Empty => write!(f, "предмет счёта пуст — считать некого"),
            MemberRefusal::TooLong { max, got } => {
                write!(f, "предмет счёта длиннее {max} символов — получено {got}")
            }
            MemberRefusal::NotPrintable => {
                write!(f, "предмет счёта содержит пробел или управляющий символ")
            }
        }
    }
}

impl std::error::Error for MemberRefusal {}

#[cfg(test)]
mod tests {
    use super::MemberRefusal;

    #[test]
    fn every_refusal_says_what_was_wrong() {
        assert!(MemberRefusal::Empty.to_string().contains("пуст"));
        assert!(MemberRefusal::TooLong { max: 128, got: 129 }
            .to_string()
            .contains("128"));
        assert!(MemberRefusal::NotPrintable
            .to_string()
            .contains("управляющий"));
    }
}
