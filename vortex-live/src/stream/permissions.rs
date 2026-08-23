use serde::{Deserialize, Serialize};

use crate::stream::role::StreamRole;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    pub can_speak: bool,
    pub can_video: bool,
    pub can_screen_share: bool,
}

impl Permissions {
    pub fn of(role: StreamRole) -> Self {
        Permissions {
            can_speak: role != StreamRole::Viewer,
            can_video: role != StreamRole::Viewer,
            can_screen_share: role.runs_the_stream(),
        }
    }

    pub fn granting(self, speak: Option<bool>, video: Option<bool>, screen: Option<bool>) -> Self {
        Permissions {
            can_speak: speak.unwrap_or(self.can_speak),
            can_video: video.unwrap_or(self.can_video),
            can_screen_share: screen.unwrap_or(self.can_screen_share),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Permissions;
    use crate::stream::role::StreamRole;

    #[test]
    fn the_host_may_do_everything_the_stream_allows() {
        let allowed = Permissions::of(StreamRole::Host);
        assert!(allowed.can_speak);
        assert!(allowed.can_video);
        assert!(allowed.can_screen_share);
    }

    #[test]
    fn a_speaker_speaks_and_shows_video_but_shares_no_screen() {
        let allowed = Permissions::of(StreamRole::Speaker);
        assert!(allowed.can_speak);
        assert!(allowed.can_video);
        assert!(!allowed.can_screen_share);
    }

    #[test]
    fn a_viewer_only_watches() {
        let allowed = Permissions::of(StreamRole::Viewer);
        assert!(!allowed.can_speak);
        assert!(!allowed.can_video);
        assert!(!allowed.can_screen_share);
    }

    #[test]
    fn a_grant_that_names_nothing_changes_nothing() {
        let allowed = Permissions::of(StreamRole::Speaker);
        assert_eq!(allowed.granting(None, None, None), allowed);
    }

    #[test]
    fn a_grant_changes_only_what_it_names() {
        let allowed = Permissions::of(StreamRole::Viewer).granting(Some(true), None, None);
        assert!(allowed.can_speak);
        assert!(!allowed.can_video);
    }
}
