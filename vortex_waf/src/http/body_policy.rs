use crate::http::responses::http_response::HttpResponse;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyPolicy {
    Skip,
    Reject(Box<HttpResponse>),
    InspectHead,
    BufferBody { limit: usize },
}

impl BodyPolicy {
    pub fn reject(response: HttpResponse) -> Self {
        BodyPolicy::Reject(Box::new(response))
    }

    pub fn is_skip(&self) -> bool {
        matches!(self, BodyPolicy::Skip)
    }

    pub fn reads_body(&self) -> bool {
        matches!(self, BodyPolicy::BufferBody { .. })
    }

    pub fn body_limit(&self) -> usize {
        match self {
            BodyPolicy::BufferBody { limit } => *limit,
            _ => 0,
        }
    }

    pub fn response(&self) -> Option<&HttpResponse> {
        match self {
            BodyPolicy::Reject(response) => Some(response),
            _ => None,
        }
    }

    pub fn status(&self) -> Option<u16> {
        self.response().map(|r| r.status)
    }
}

#[cfg(test)]
mod tests {
    use super::BodyPolicy;
    use crate::http::responses::too_large;

    #[test]
    fn only_buffering_reports_a_limit() {
        assert_eq!(BodyPolicy::BufferBody { limit: 64 }.body_limit(), 64);
        assert!(BodyPolicy::BufferBody { limit: 64 }.reads_body());
        assert_eq!(BodyPolicy::InspectHead.body_limit(), 0);
        assert!(!BodyPolicy::InspectHead.reads_body());
        assert!(BodyPolicy::Skip.is_skip());
    }

    #[test]
    fn rejection_carries_the_response() {
        let policy = BodyPolicy::reject(too_large::build(128));
        assert_eq!(policy.status(), Some(413));
        assert!(!policy.reads_body());
    }
}
