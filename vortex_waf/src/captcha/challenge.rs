//! Выданная задача-капча.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Challenge {
    /// Самодостаточный идентификатор: в нём же лежит подпись ответа.
    pub challenge_id: String,
    pub question: String,
    pub expires_in: u64,
}

impl Challenge {
    pub fn new(
        challenge_id: impl Into<String>,
        question: impl Into<String>,
        expires_in: u64,
    ) -> Self {
        Challenge {
            challenge_id: challenge_id.into(),
            question: question.into(),
            expires_in,
        }
    }
}
