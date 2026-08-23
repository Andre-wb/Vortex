use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushRefusal {
    ShortToken,
    OverLongToken,
    TokenOutsideAlphabet,
    ShortEndpoint,
    OverLongEndpoint,
    EndpointOutsideAlphabet,
    NoCategories,
    TooManyCategories,
}

impl PushRefusal {
    pub fn message(&self) -> String {
        match self {
            PushRefusal::ShortToken => format!(
                "Push token shorter than {} characters",
                super::limits::MIN_TOKEN_LENGTH
            ),
            PushRefusal::OverLongToken => format!(
                "Push token longer than {} characters",
                super::limits::MAX_TOKEN_LENGTH
            ),
            PushRefusal::TokenOutsideAlphabet => "Push token holds a control character".to_owned(),
            PushRefusal::ShortEndpoint => format!(
                "Push endpoint shorter than {} characters",
                super::limits::MIN_ENDPOINT_LENGTH
            ),
            PushRefusal::OverLongEndpoint => format!(
                "Push endpoint longer than {} characters",
                super::limits::MAX_ENDPOINT_LENGTH
            ),
            PushRefusal::EndpointOutsideAlphabet => {
                "Push endpoint holds a space or a control character".to_owned()
            }
            PushRefusal::NoCategories => "At least one category is required".to_owned(),
            PushRefusal::TooManyCategories => format!(
                "More than {} categories named",
                super::limits::CATEGORY_COUNT
            ),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            PushRefusal::ShortToken => "push_token_short",
            PushRefusal::OverLongToken => "push_token_long",
            PushRefusal::TokenOutsideAlphabet => "push_token_alphabet",
            PushRefusal::ShortEndpoint => "push_endpoint_short",
            PushRefusal::OverLongEndpoint => "push_endpoint_long",
            PushRefusal::EndpointOutsideAlphabet => "push_endpoint_alphabet",
            PushRefusal::NoCategories => "categories_required",
            PushRefusal::TooManyCategories => "categories_many",
        }
    }
}

impl fmt::Display for PushRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for PushRefusal {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushStateError {
    Unavailable,
}

impl fmt::Display for PushStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PushStateError::Unavailable => write!(
                f,
                "общее состояние пуш-прокси недоступно — операция не выполнена"
            ),
        }
    }
}

impl std::error::Error for PushStateError {}

pub type Result<T> = std::result::Result<T, PushStateError>;

#[cfg(test)]
mod tests {
    use super::PushRefusal;

    const EVERY: [PushRefusal; 8] = [
        PushRefusal::ShortToken,
        PushRefusal::OverLongToken,
        PushRefusal::TokenOutsideAlphabet,
        PushRefusal::ShortEndpoint,
        PushRefusal::OverLongEndpoint,
        PushRefusal::EndpointOutsideAlphabet,
        PushRefusal::NoCategories,
        PushRefusal::TooManyCategories,
    ];

    #[test]
    fn every_refusal_can_be_told_to_a_client() {
        for refusal in EVERY {
            assert!(!refusal.message().is_empty());
            assert!(refusal.message().is_ascii());
            assert!(!refusal.code().is_empty());
        }
    }
}
