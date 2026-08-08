#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameStep {
    Opened { consumed: usize, body: Vec<u8> },
    NeedMore,
    Malformed,
}

impl FrameStep {
    pub fn name(&self) -> &'static str {
        match self {
            FrameStep::Opened { .. } => "opened",
            FrameStep::NeedMore => "need_more",
            FrameStep::Malformed => "malformed",
        }
    }

    pub fn is_opened(&self) -> bool {
        matches!(self, FrameStep::Opened { .. })
    }

    pub fn needs_more(&self) -> bool {
        matches!(self, FrameStep::NeedMore)
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, FrameStep::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::FrameStep;

    #[test]
    fn every_outcome_says_what_it_is() {
        let opened = FrameStep::Opened {
            consumed: 1,
            body: Vec::new(),
        };
        assert_eq!(opened.name(), "opened");
        assert!(opened.is_opened());
        assert_eq!(FrameStep::NeedMore.name(), "need_more");
        assert!(FrameStep::NeedMore.needs_more());
        assert_eq!(FrameStep::Malformed.name(), "malformed");
        assert!(FrameStep::Malformed.is_malformed());
    }

    #[test]
    fn the_three_outcomes_never_overlap() {
        assert!(!FrameStep::NeedMore.is_malformed());
        assert!(!FrameStep::Malformed.needs_more());
        assert!(!FrameStep::NeedMore.is_opened());
    }
}
