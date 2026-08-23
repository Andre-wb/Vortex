use serde::{Deserialize, Serialize};

pub const HOST: &str = "host";
pub const CO_HOST: &str = "co_host";
pub const SPEAKER: &str = "speaker";
pub const VIEWER: &str = "viewer";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamRole {
    #[serde(rename = "host")]
    Host,
    #[serde(rename = "co_host")]
    CoHost,
    #[serde(rename = "speaker")]
    Speaker,
    #[serde(rename = "viewer")]
    Viewer,
}

impl StreamRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            CO_HOST => Some(StreamRole::CoHost),
            SPEAKER => Some(StreamRole::Speaker),
            VIEWER => Some(StreamRole::Viewer),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            StreamRole::Host => HOST,
            StreamRole::CoHost => CO_HOST,
            StreamRole::Speaker => SPEAKER,
            StreamRole::Viewer => VIEWER,
        }
    }

    pub fn runs_the_stream(self) -> bool {
        matches!(self, StreamRole::Host | StreamRole::CoHost)
    }
}

#[cfg(test)]
mod tests {
    use super::StreamRole;

    #[test]
    fn the_roles_the_host_may_grant_are_read() {
        assert_eq!(StreamRole::parse("co_host"), Some(StreamRole::CoHost));
        assert_eq!(StreamRole::parse("speaker"), Some(StreamRole::Speaker));
        assert_eq!(StreamRole::parse("viewer"), Some(StreamRole::Viewer));
    }

    #[test]
    fn the_host_role_is_never_granted_by_a_request() {
        assert_eq!(StreamRole::parse("host"), None);
        assert_eq!(StreamRole::parse(""), None);
    }

    #[test]
    fn only_the_host_and_the_co_host_run_the_stream() {
        assert!(StreamRole::Host.runs_the_stream());
        assert!(StreamRole::CoHost.runs_the_stream());
        assert!(!StreamRole::Speaker.runs_the_stream());
        assert!(!StreamRole::Viewer.runs_the_stream());
    }

    #[test]
    fn a_role_survives_the_trip_back_to_the_client() {
        assert_eq!(StreamRole::Host.as_str(), "host");
        assert_eq!(StreamRole::CoHost.as_str(), "co_host");
    }
}
