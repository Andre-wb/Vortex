use crate::wrap::envelope::WrappedKey;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapView {
    pub hybrid: bool,
    pub ephemeral_pub: String,
    pub kyber_ciphertext: Option<String>,
    pub ciphertext: String,
}

impl WrapView {
    pub fn of(wrapped: &WrappedKey) -> Self {
        WrapView {
            hybrid: wrapped.is_hybrid(),
            ephemeral_pub: wrapped.ephemeral_public().to_hex(),
            kyber_ciphertext: wrapped.kyber_ciphertext().map(|value| value.to_hex()),
            ciphertext: wrapped.ciphertext().to_hex(),
        }
    }

    pub fn stored(ephemeral_pub: &str, ciphertext: &str, kyber_ciphertext: Option<&str>) -> Self {
        let kyber = kyber_ciphertext.filter(|value| !value.is_empty());
        WrapView {
            hybrid: kyber.is_some(),
            ephemeral_pub: ephemeral_pub.to_string(),
            kyber_ciphertext: kyber.map(|value| value.to_string()),
            ciphertext: ciphertext.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WrapView;
    use crate::wrap::envelope::WrappedKey;
    use crate::wrap::limits::KYBER_CIPHERTEXT_LEN;
    use crate::wrap::request::WrapRequest;

    fn parsed(request: WrapRequest) -> WrappedKey {
        WrappedKey::parse(&request).unwrap()
    }

    #[test]
    fn a_classical_envelope_is_shown_without_kyber_fields() {
        let view = WrapView::of(&parsed(WrapRequest {
            ephemeral_pub: Some("1a".repeat(32)),
            ciphertext: "2b".repeat(60),
            ..WrapRequest::default()
        }));
        assert!(!view.hybrid);
        assert_eq!(view.ephemeral_pub, "1a".repeat(32));
        assert_eq!(view.kyber_ciphertext, None);
    }

    #[test]
    fn a_hybrid_envelope_is_shown_with_its_kyber_ciphertext() {
        let view = WrapView::of(&parsed(WrapRequest {
            ciphertext: "2b".repeat(60),
            hybrid: Some(true),
            x25519_ephemeral_pub: Some("1a".repeat(32)),
            kyber_ciphertext: Some("3c".repeat(KYBER_CIPHERTEXT_LEN)),
            ..WrapRequest::default()
        }));
        assert!(view.hybrid);
        assert_eq!(
            view.kyber_ciphertext,
            Some("3c".repeat(KYBER_CIPHERTEXT_LEN))
        );
    }

    #[test]
    fn a_stored_row_is_hybrid_exactly_when_it_kept_a_kyber_ciphertext() {
        let classical = WrapView::stored("1a", "2b", None);
        let hybrid = WrapView::stored("1a", "2b", Some("3c"));
        assert!(!classical.hybrid);
        assert!(hybrid.hybrid);
    }

    #[test]
    fn a_stored_row_with_an_empty_kyber_column_is_classical() {
        let view = WrapView::stored("1a", "2b", Some(""));
        assert!(!view.hybrid);
        assert_eq!(view.kyber_ciphertext, None);
    }

    #[test]
    fn what_was_parsed_is_what_is_shown_back() {
        let request = WrapRequest {
            ciphertext: "2b".repeat(60),
            hybrid: Some(true),
            x25519_ephemeral_pub: Some("1a".repeat(32)),
            kyber_ciphertext: Some("3c".repeat(KYBER_CIPHERTEXT_LEN)),
            ..WrapRequest::default()
        };
        let view = WrapView::of(&parsed(request));
        let stored = WrapView::stored(
            &view.ephemeral_pub,
            &view.ciphertext,
            view.kyber_ciphertext.as_deref(),
        );
        assert_eq!(view, stored);
    }
}
