use crate::dns::name::{MAX_LABEL, MAX_NAME};
use crate::doh::base32;
use crate::doh::chunk::{Chunk, HEADER, MAX_CHUNKS};

pub const DEFAULT_SUFFIX: &str = "cdn-sync.net";

#[derive(Debug, Clone)]
pub struct DohTunnel {
    suffix: String,
    payload: usize,
}

impl DohTunnel {
    pub fn under(suffix: &str) -> Option<DohTunnel> {
        let trimmed = suffix.trim_matches('.');
        let room = room_under(trimmed)?;
        if room <= HEADER {
            return None;
        }
        Some(DohTunnel {
            suffix: trimmed.to_owned(),
            payload: room - HEADER,
        })
    }

    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    pub fn payload_per_query(&self) -> usize {
        self.payload
    }

    pub fn encode(&self, data: &[u8], message: u16) -> Option<Vec<String>> {
        let pieces: Vec<&[u8]> = if data.is_empty() {
            vec![data]
        } else {
            data.chunks(self.payload).collect()
        };
        if pieces.len() > MAX_CHUNKS {
            return None;
        }
        let total = pieces.len() as u16;
        Some(
            pieces
                .into_iter()
                .enumerate()
                .map(|(index, piece)| {
                    let header = Chunk {
                        message,
                        total,
                        index: index as u16,
                    };
                    self.named(&base32::encode(&header.written(piece)))
                })
                .collect(),
        )
    }

    pub fn decode(&self, fqdn: &str) -> Option<(Chunk, Vec<u8>)> {
        let bare = fqdn.trim_end_matches('.');
        let head = bare
            .strip_suffix(&self.suffix)
            .and_then(|rest| rest.strip_suffix('.'))?;
        if head.is_empty() {
            return None;
        }
        let encoded: String = head.split('.').collect();
        Chunk::read(&base32::decode(&encoded)?)
    }

    fn named(&self, encoded: &str) -> String {
        let mut labels: Vec<&str> = Vec::new();
        let bytes = encoded.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            let end = (at + MAX_LABEL).min(bytes.len());
            labels.push(&encoded[at..end]);
            at = end;
        }
        labels.push(&self.suffix);
        labels.join(".")
    }
}

pub fn wire_length(name: &str) -> usize {
    name.trim_end_matches('.')
        .split('.')
        .map(|label| 1 + label.len())
        .sum::<usize>()
        + 1
}

fn room_under(suffix: &str) -> Option<usize> {
    if suffix.is_empty() {
        return None;
    }
    let taken = wire_length(suffix);
    if taken >= MAX_NAME {
        return None;
    }
    let free = MAX_NAME - taken;
    let mut best = 0;
    for raw in 1..=free {
        let encoded = base32::encoded_length(raw);
        let cost = encoded + encoded.div_ceil(MAX_LABEL);
        if cost <= free {
            best = raw;
        }
    }
    if best == 0 {
        return None;
    }
    Some(best)
}

#[cfg(test)]
mod tests {
    use super::{wire_length, DohTunnel, DEFAULT_SUFFIX};
    use crate::dns::name::{self, MAX_LABEL, MAX_NAME};
    use crate::doh::chunk::Chunk;

    fn tunnel() -> DohTunnel {
        DohTunnel::under(DEFAULT_SUFFIX).unwrap()
    }

    #[test]
    fn what_was_encoded_comes_back_out_of_the_names() {
        let tunnel = tunnel();
        for length in [0usize, 1, 50, 141, 142, 143, 500, 4096] {
            let payload: Vec<u8> = (0..length).map(|index| (index * 13 % 256) as u8).collect();
            let names = tunnel.encode(&payload, 42).unwrap();
            let mut rebuilt = Vec::new();
            for (index, fqdn) in names.iter().enumerate() {
                let (chunk, piece) = tunnel.decode(fqdn).unwrap();
                assert_eq!(chunk.message, 42);
                assert_eq!(chunk.index as usize, index);
                assert_eq!(chunk.total as usize, names.len());
                rebuilt.extend_from_slice(&piece);
            }
            assert_eq!(rebuilt, payload, "длина {length}");
        }
    }

    #[test]
    fn every_name_a_query_is_sent_under_is_a_name_dns_accepts() {
        let tunnel = tunnel();
        let payload = vec![0xABu8; 10_000];
        for fqdn in tunnel.encode(&payload, 1).unwrap() {
            assert!(
                wire_length(&fqdn) <= MAX_NAME,
                "имя длиной {} байт: {fqdn}",
                wire_length(&fqdn)
            );
            assert!(name::encode(&fqdn).is_some(), "непредставимое имя: {fqdn}");
            for label in fqdn.split('.') {
                assert!(!label.is_empty());
                assert!(label.len() <= MAX_LABEL);
            }
        }
    }

    #[test]
    fn a_longer_suffix_leaves_less_room_for_data() {
        let short = DohTunnel::under("a.io").unwrap();
        let long = DohTunnel::under("very-long-tunnel-domain-name.example.org").unwrap();
        assert!(short.payload_per_query() > long.payload_per_query());
        assert!(long.payload_per_query() > 0);
    }

    #[test]
    fn a_suffix_that_leaves_no_room_is_refused_instead_of_producing_broken_names() {
        let huge = vec!["abcdefghij"; 25].join(".");
        assert!(DohTunnel::under(&huge).is_none());
        assert!(DohTunnel::under("").is_none());
        assert!(DohTunnel::under(".").is_none());
    }

    #[test]
    fn a_name_from_another_tunnel_is_not_read_as_ours() {
        let tunnel = tunnel();
        assert_eq!(tunnel.decode("mzxw6ytb.example.org"), None);
        assert_eq!(tunnel.decode(DEFAULT_SUFFIX), None);
        assert_eq!(tunnel.decode(""), None);
    }

    #[test]
    fn a_name_that_is_not_this_encoding_is_refused() {
        let tunnel = tunnel();
        assert_eq!(tunnel.decode(&format!("!!!!!!!!.{DEFAULT_SUFFIX}")), None);
        assert_eq!(tunnel.decode(&format!("a.{DEFAULT_SUFFIX}")), None);
    }

    #[test]
    fn the_trailing_dot_a_resolver_may_add_does_not_change_the_answer() {
        let tunnel = tunnel();
        let name = tunnel.encode(b"hello", 3).unwrap().remove(0);
        assert_eq!(tunnel.decode(&format!("{name}.")), tunnel.decode(&name));
    }

    #[test]
    fn nothing_to_send_is_still_one_query_and_not_none() {
        let tunnel = tunnel();
        let names = tunnel.encode(b"", 9).unwrap();
        assert_eq!(names.len(), 1);
        let (chunk, piece) = tunnel.decode(&names[0]).unwrap();
        assert_eq!(
            chunk,
            Chunk {
                message: 9,
                total: 1,
                index: 0
            }
        );
        assert!(piece.is_empty());
    }

    #[test]
    fn a_message_too_large_to_number_its_chunks_is_refused() {
        let tunnel = tunnel();
        let enormous = vec![0u8; tunnel.payload_per_query() * (u16::MAX as usize + 1)];
        assert_eq!(tunnel.encode(&enormous, 0), None);
    }
}
