use crate::error::BmpError;
use crate::store::refusal::DepositRefusal;

pub const STATUS_BAD_REQUEST: u16 = 400;
pub const STATUS_PAYLOAD_TOO_LARGE: u16 = 413;
pub const STATUS_TOO_MANY_REQUESTS: u16 = 429;
pub const STATUS_STORAGE_FULL: u16 = 503;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub status: u16,
    pub detail: String,
}

impl Rejection {
    pub fn rate_limited() -> Self {
        Rejection {
            status: STATUS_TOO_MANY_REQUESTS,
            detail: "Rate limit exceeded".to_string(),
        }
    }

    pub fn invalid_mailbox_id(error: &BmpError) -> Self {
        let detail = match error {
            BmpError::MailboxIdLength { .. } => "Invalid mailbox ID length",
            _ => "Invalid mailbox ID",
        };
        Rejection {
            status: STATUS_BAD_REQUEST,
            detail: detail.to_string(),
        }
    }

    pub fn invalid_secret(error: &BmpError) -> Self {
        let detail = match error {
            BmpError::SecretLength { .. } => "Invalid BMP secret length",
            _ => "Invalid BMP secret",
        };
        Rejection {
            status: STATUS_BAD_REQUEST,
            detail: detail.to_string(),
        }
    }

    pub fn message_too_short(minimum: usize) -> Self {
        Rejection {
            status: STATUS_BAD_REQUEST,
            detail: format!("Message shorter than {minimum} characters"),
        }
    }

    pub fn refused_deposit(refusal: DepositRefusal) -> Self {
        match refusal {
            DepositRefusal::TooLarge => Rejection {
                status: STATUS_PAYLOAD_TOO_LARGE,
                detail: "Message too large".to_string(),
            },
            DepositRefusal::AtCapacity => Rejection {
                status: STATUS_STORAGE_FULL,
                detail: "Mailbox storage full".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rejection;
    use crate::error::BmpError;
    use crate::store::refusal::DepositRefusal;

    #[test]
    fn a_short_identifier_is_reported_as_a_bad_request() {
        let rejection = Rejection::invalid_mailbox_id(&BmpError::MailboxIdLength {
            min: 16,
            max: 64,
            got: 3,
        });
        assert_eq!(rejection.status, 400);
        assert_eq!(rejection.detail, "Invalid mailbox ID length");
    }

    #[test]
    fn a_non_hex_identifier_is_reported_as_a_bad_request() {
        let rejection = Rejection::invalid_mailbox_id(&BmpError::MailboxIdNotHex);
        assert_eq!(rejection.status, 400);
        assert_eq!(rejection.detail, "Invalid mailbox ID");
    }

    #[test]
    fn an_oversized_message_and_a_full_store_are_told_apart() {
        assert_eq!(
            Rejection::refused_deposit(DepositRefusal::TooLarge).status,
            413
        );
        assert_eq!(
            Rejection::refused_deposit(DepositRefusal::AtCapacity).status,
            503
        );
    }

    #[test]
    fn exceeding_the_rate_limit_is_reported_as_too_many_requests() {
        assert_eq!(Rejection::rate_limited().status, 429);
    }
}
