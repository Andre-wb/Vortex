#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MutePatch {
    pub muted: Option<bool>,
    pub video: Option<bool>,
}

impl MutePatch {
    pub fn new(muted: Option<bool>, video: Option<bool>) -> Self {
        MutePatch { muted, video }
    }

    pub fn muted_after(&self, before: bool) -> bool {
        match self.muted {
            Some(value) => value,
            None => !before,
        }
    }

    pub fn video_after(&self, before: bool) -> bool {
        self.video.unwrap_or(before)
    }
}

#[cfg(test)]
mod tests {
    use super::MutePatch;

    #[test]
    fn a_patch_without_a_mute_flag_flips_the_one_that_is_there() {
        let patch = MutePatch::new(None, None);
        assert!(patch.muted_after(false));
        assert!(!patch.muted_after(true));
    }

    #[test]
    fn a_patch_with_a_mute_flag_says_what_it_becomes() {
        assert!(MutePatch::new(Some(true), None).muted_after(true));
        assert!(!MutePatch::new(Some(false), None).muted_after(true));
    }

    #[test]
    fn a_patch_without_a_video_flag_leaves_video_alone() {
        assert!(MutePatch::new(None, None).video_after(true));
        assert!(!MutePatch::new(None, None).video_after(false));
    }

    #[test]
    fn a_patch_with_a_video_flag_says_what_it_becomes() {
        assert!(MutePatch::new(None, Some(true)).video_after(false));
        assert!(!MutePatch::new(None, Some(false)).video_after(true));
    }
}
