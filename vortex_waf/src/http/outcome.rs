//! Что транспорту делать с запросом.

use crate::http::responses::http_response::HttpResponse;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardOutcome {
    /// Передать запрос приложению.
    Pass,
    /// Ответить самому, приложение не трогать.
    Reject(Box<HttpResponse>),
}

impl GuardOutcome {
    pub fn reject(response: HttpResponse) -> Self {
        GuardOutcome::Reject(Box::new(response))
    }

    pub fn is_pass(&self) -> bool {
        matches!(self, GuardOutcome::Pass)
    }

    pub fn response(&self) -> Option<&HttpResponse> {
        match self {
            GuardOutcome::Pass => None,
            GuardOutcome::Reject(response) => Some(response),
        }
    }

    pub fn status(&self) -> Option<u16> {
        self.response().map(|r| r.status)
    }
}
