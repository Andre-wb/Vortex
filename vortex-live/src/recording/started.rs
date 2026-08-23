use crate::recording::mark::Mark;

#[derive(Debug, Clone, PartialEq)]
pub enum Started {
    Fresh(Mark),
    Already(Mark),
}

impl Started {
    pub fn already_started(&self) -> bool {
        matches!(self, Started::Already(_))
    }

    pub fn mark(&self) -> &Mark {
        match self {
            Started::Fresh(mark) | Started::Already(mark) => mark,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Started;
    use crate::recording::mark::Mark;

    fn mark() -> Mark {
        Mark::new(7, "2026-08-04T09:15:30+00:00".to_owned(), vec![], 1_120.0)
    }

    #[test]
    fn a_first_start_is_not_a_repeat() {
        assert!(!Started::Fresh(mark()).already_started());
        assert_eq!(Started::Fresh(mark()).mark(), &mark());
    }

    #[test]
    fn a_repeat_start_gives_back_the_recording_that_is_already_running() {
        assert!(Started::Already(mark()).already_started());
    }
}
