use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct WrapRequest {
    #[serde(default)]
    pub ephemeral_pub: Option<String>,
    #[serde(default)]
    pub ciphertext: String,
    #[serde(default)]
    pub hybrid: Option<bool>,
    #[serde(default)]
    pub x25519_ephemeral_pub: Option<String>,
    #[serde(default)]
    pub kyber_ciphertext: Option<String>,
}

impl WrapRequest {
    pub fn from_json(payload: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(payload)
    }

    pub fn classical_ephemeral_text(&self) -> Option<&str> {
        present(self.ephemeral_pub.as_deref())
    }

    pub fn hybrid_ephemeral_text(&self) -> Option<&str> {
        present(self.x25519_ephemeral_pub.as_deref())
    }

    pub fn kyber_text(&self) -> Option<&str> {
        present(self.kyber_ciphertext.as_deref())
    }

    pub fn claims_hybrid(&self) -> bool {
        self.hybrid == Some(true) || self.kyber_text().is_some()
    }
}

fn present(text: Option<&str>) -> Option<&str> {
    text.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::WrapRequest;

    #[test]
    fn a_classical_payload_names_its_ephemeral_key() {
        let request =
            WrapRequest::from_json(r#"{"ephemeral_pub":"ab","ciphertext":"cd"}"#).unwrap();
        assert_eq!(request.classical_ephemeral_text(), Some("ab"));
        assert_eq!(request.kyber_text(), None);
        assert!(!request.claims_hybrid());
    }

    #[test]
    fn a_hybrid_payload_carries_its_own_ephemeral_field() {
        let request = WrapRequest::from_json(
            r#"{"hybrid":true,"x25519_ephemeral_pub":"22","kyber_ciphertext":"33","ciphertext":"cd"}"#,
        )
        .unwrap();
        assert_eq!(request.hybrid_ephemeral_text(), Some("22"));
        assert_eq!(request.kyber_text(), Some("33"));
        assert!(request.claims_hybrid());
    }

    #[test]
    fn a_kyber_ciphertext_alone_makes_the_payload_hybrid() {
        let request = WrapRequest::from_json(
            r#"{"ephemeral_pub":"11","kyber_ciphertext":"33","ciphertext":"cd"}"#,
        )
        .unwrap();
        assert!(request.claims_hybrid());
    }

    #[test]
    fn an_empty_string_is_the_same_as_an_absent_field() {
        let request =
            WrapRequest::from_json(r#"{"ephemeral_pub":"","kyber_ciphertext":"","ciphertext":""}"#)
                .unwrap();
        assert_eq!(request.classical_ephemeral_text(), None);
        assert_eq!(request.kyber_text(), None);
        assert!(!request.claims_hybrid());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let request =
            WrapRequest::from_json(r#"{"ephemeral_pub":"ab","ciphertext":"cd","extra":1}"#)
                .unwrap();
        assert_eq!(request.ciphertext, "cd");
    }
}
