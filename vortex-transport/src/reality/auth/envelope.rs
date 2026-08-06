use crate::reality::short_id::value::ShortId;

pub const ENVELOPE_VERSION: u8 = 1;
pub const ENVELOPE_HEADER_LEN: usize = 9;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u8,
    pub timestamp: i64,
    pub short_id: ShortId,
}

impl Envelope {
    pub fn current(timestamp: i64, short_id: ShortId) -> Self {
        Envelope {
            version: ENVELOPE_VERSION,
            timestamp,
            short_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_HEADER_LEN + self.short_id.len());
        out.push(self.version);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(self.short_id.as_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ENVELOPE_HEADER_LEN {
            return None;
        }
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&bytes[1..ENVELOPE_HEADER_LEN]);
        Some(Envelope {
            version: bytes[0],
            timestamp: i64::from_be_bytes(timestamp),
            short_id: ShortId::from_bytes(&bytes[ENVELOPE_HEADER_LEN..]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Envelope, ENVELOPE_VERSION};
    use crate::reality::short_id::value::ShortId;

    #[test]
    fn encodes_version_timestamp_and_short_id() {
        let envelope = Envelope::current(1, ShortId::from_hex("deadbeef").unwrap());
        assert_eq!(hex::encode(envelope.encode()), "010000000000000001deadbeef");
    }

    #[test]
    fn round_trips() {
        let envelope = Envelope::current(1_760_000_000, ShortId::from_hex("cafebabe").unwrap());
        assert_eq!(Envelope::decode(&envelope.encode()), Some(envelope));
    }

    #[test]
    fn rejects_a_truncated_header() {
        assert_eq!(Envelope::decode(&[0u8; 8]), None);
    }

    #[test]
    fn accepts_an_empty_short_id() {
        let decoded = Envelope::decode(&[ENVELOPE_VERSION, 0, 0, 0, 0, 0, 0, 0, 7]).unwrap();
        assert_eq!(decoded.timestamp, 7);
        assert!(decoded.short_id.is_empty());
    }

    #[test]
    fn preserves_negative_timestamps() {
        let envelope = Envelope::current(-1, ShortId::from_bytes(vec![]));
        assert_eq!(Envelope::decode(&envelope.encode()).unwrap().timestamp, -1);
    }
}
