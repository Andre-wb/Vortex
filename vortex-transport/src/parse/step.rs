#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step<T> {
    Parsed { value: T, consumed: usize },
    NeedMore,
    Malformed,
}

impl<T> Step<T> {
    pub fn parsed(value: T, consumed: usize) -> Self {
        Step::Parsed { value, consumed }
    }

    pub fn value(self) -> Option<T> {
        match self {
            Step::Parsed { value, .. } => Some(value),
            _ => None,
        }
    }

    pub fn needs_more(&self) -> bool {
        matches!(self, Step::NeedMore)
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, Step::Malformed)
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Step<U> {
        match self {
            Step::Parsed { value, consumed } => Step::parsed(f(value), consumed),
            Step::NeedMore => Step::NeedMore,
            Step::Malformed => Step::Malformed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Step;

    #[test]
    fn a_parsed_step_carries_what_it_consumed() {
        let step = Step::parsed(7u8, 3);
        assert_eq!(step.clone().value(), Some(7));
        assert!(!step.needs_more());
        assert_eq!(
            step,
            Step::Parsed {
                value: 7,
                consumed: 3
            }
        );
    }

    #[test]
    fn an_incomplete_step_carries_nothing() {
        let step: Step<u8> = Step::NeedMore;
        assert!(step.needs_more());
        assert_eq!(step.value(), None);
    }

    #[test]
    fn mapping_keeps_the_consumed_length() {
        let step = Step::parsed(2u8, 5).map(u16::from);
        assert_eq!(step, Step::parsed(2u16, 5));
    }

    #[test]
    fn mapping_leaves_a_refusal_alone() {
        let step: Step<u8> = Step::Malformed;
        assert!(step.map(u16::from).is_malformed());
    }
}
