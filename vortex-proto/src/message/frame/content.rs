use crate::message::ciphertext::MessageCiphertext;
use crate::message::digest::ContentDigest;
use crate::message::enc_version::EncVersion;
use crate::message::frame::incoming::IncomingFrame;
use crate::message::refusal::MessageRefusal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageContent {
    pub ciphertext: MessageCiphertext,
    pub digest: ContentDigest,
    pub digest_claim: DigestClaim,
    pub enc_version: Option<EncVersion>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestClaim {
    Absent,
    Truthful,
    Untruthful,
}

impl MessageContent {
    pub fn read(frame: &IncomingFrame) -> Result<Self, MessageRefusal> {
        let ciphertext = MessageCiphertext::parse_hex(frame.text("ciphertext"))?;
        let digest = ContentDigest::of(ciphertext.as_bytes());
        let claim = frame.text("hash");
        let digest_claim = if claim.is_empty() {
            DigestClaim::Absent
        } else if digest.is_claimed_truthfully(claim) {
            DigestClaim::Truthful
        } else {
            DigestClaim::Untruthful
        };
        Ok(MessageContent {
            ciphertext,
            digest,
            digest_claim,
            enc_version: EncVersion::read(frame.field("enc_v")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{DigestClaim, MessageContent};
    use crate::message::digest::ContentDigest;
    use crate::message::frame::incoming::IncomingFrame;
    use crate::message::refusal::MessageRefusal;

    fn frame(payload: &str) -> IncomingFrame {
        IncomingFrame::from_json(payload).unwrap()
    }

    fn ciphertext_hex() -> String {
        "ab".repeat(30)
    }

    #[test]
    fn the_digest_is_computed_from_the_ciphertext_that_arrived() {
        let content = MessageContent::read(&frame(&format!(
            r#"{{"ciphertext":"{}"}}"#,
            ciphertext_hex()
        )))
        .unwrap();
        assert_eq!(
            content.digest,
            ContentDigest::of(&hex_bytes(&ciphertext_hex()))
        );
        assert_eq!(content.digest_claim, DigestClaim::Absent);
        assert_eq!(content.enc_version, None);
    }

    #[test]
    fn a_truthful_claim_is_recognised_and_changes_nothing() {
        let honest = ContentDigest::of(&hex_bytes(&ciphertext_hex())).to_hex();
        let content = MessageContent::read(&frame(&format!(
            r#"{{"ciphertext":"{}","hash":"{honest}"}}"#,
            ciphertext_hex()
        )))
        .unwrap();
        assert_eq!(content.digest_claim, DigestClaim::Truthful);
        assert_eq!(content.digest.to_hex(), honest);
    }

    #[test]
    fn a_claim_that_does_not_match_never_becomes_the_digest() {
        let content = MessageContent::read(&frame(&format!(
            r#"{{"ciphertext":"{}","hash":"{}"}}"#,
            ciphertext_hex(),
            "11".repeat(32)
        )))
        .unwrap();
        assert_eq!(content.digest_claim, DigestClaim::Untruthful);
        assert_eq!(
            content.digest,
            ContentDigest::of(&hex_bytes(&ciphertext_hex()))
        );
    }

    #[test]
    fn the_envelope_version_is_read_alongside_the_content() {
        let content = MessageContent::read(&frame(&format!(
            r#"{{"ciphertext":"{}","enc_v":2}}"#,
            ciphertext_hex()
        )))
        .unwrap();
        assert_eq!(content.enc_version.unwrap().value(), 2);
    }

    #[test]
    fn a_missing_ciphertext_is_refused_before_anything_else_is_read() {
        assert_eq!(
            MessageContent::read(&frame(r#"{"enc_v":2,"hash":"zz"}"#)),
            Err(MessageRefusal::CiphertextMissing)
        );
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        crate::hex::decode::decode(text).unwrap()
    }
}
