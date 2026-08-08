#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameStep {
    Opened { consumed: usize, data: Vec<u8> },
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
}

#[cfg(test)]
mod tests {
    use super::FrameStep;

    #[test]
    fn every_outcome_says_what_it_is() {
        assert_eq!(
            FrameStep::Opened {
                consumed: 1,
                data: Vec::new()
            }
            .name(),
            "opened"
        );
        assert_eq!(FrameStep::NeedMore.name(), "need_more");
        assert_eq!(FrameStep::Malformed.name(), "malformed");
    }
}
