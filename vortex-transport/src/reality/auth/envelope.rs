use crate::error::{Result, TransportError};
use crate::reality::short_id::value::{ShortId, SHORT_ID_LEN};

pub const ENVELOPE_VERSION: u8 = 2;
pub const ENVELOPE_LEN: usize = 1 + 4 + SHORT_ID_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u8,
    pub timestamp: u32,
    pub short_id: ShortId,
}

impl Envelope {
    pub fn current(timestamp: u32, short_id: ShortId) -> Result<Self> {
        if short_id.len() != SHORT_ID_LEN {
            return Err(TransportError::ShortIdLength {
                expected: SHORT_ID_LEN,
                got: short_id.len(),
            });
        }
        Ok(Envelope {
            version: ENVELOPE_VERSION,
            timestamp,
            short_id,
        })
    }

    pub fn encode(&self) -> [u8; ENVELOPE_LEN] {
        let mut out = [0u8; ENVELOPE_LEN];
        out[0] = self.version;
        out[1..5].copy_from_slice(&self.timestamp.to_be_bytes());
        out[5..].copy_from_slice(self.short_id.as_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ENVELOPE_LEN {
            return None;
        }
        let mut timestamp = [0u8; 4];
        timestamp.copy_from_slice(&bytes[1..5]);
        Some(Envelope {
            version: bytes[0],
            timestamp: u32::from_be_bytes(timestamp),
            short_id: ShortId::from_bytes(&bytes[5..]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Envelope, ENVELOPE_LEN, ENVELOPE_VERSION};
    use crate::error::TransportError;
    use crate::reality::short_id::value::ShortId;

    fn short_id() -> ShortId {
        ShortId::from_hex("deadbeef").unwrap()
    }

    #[test]
    fn encodes_version_timestamp_and_short_id() {
        let envelope = Envelope::current(1, short_id()).unwrap();
        assert_eq!(hex::encode(envelope.encode()), "0200000001deadbeef");
    }

    #[test]
    fn is_always_nine_bytes() {
        assert_eq!(ENVELOPE_LEN, 9);
        assert_eq!(Envelope::current(0, short_id()).unwrap().encode().len(), 9);
        assert_eq!(
            Envelope::current(u32::MAX, short_id())
                .unwrap()
                .encode()
                .len(),
            9
        );
    }

    #[test]
    fn round_trips() {
        let envelope = Envelope::current(1_760_000_000, short_id()).unwrap();
        assert_eq!(Envelope::decode(&envelope.encode()), Some(envelope));
    }

    #[test]
    fn carries_timestamps_past_the_i32_range() {
        let envelope = Envelope::current(4_000_000_000, short_id()).unwrap();
        assert_eq!(
            Envelope::decode(&envelope.encode()).unwrap().timestamp,
            4_000_000_000
        );
    }

    #[test]
    fn rejects_a_short_id_of_the_wrong_length() {
        assert_eq!(
            Envelope::current(0, ShortId::from_hex("dead").unwrap()),
            Err(TransportError::ShortIdLength {
                expected: 4,
                got: 2
            })
        );
    }

    #[test]
    fn decoding_demands_exactly_nine_bytes() {
        assert_eq!(Envelope::decode(&[ENVELOPE_VERSION; 8]), None);
        assert_eq!(Envelope::decode(&[ENVELOPE_VERSION; 10]), None);
        assert!(Envelope::decode(&[ENVELOPE_VERSION; 9]).is_some());
    }
}
