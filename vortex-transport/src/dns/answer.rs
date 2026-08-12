use crate::dns::name;
use crate::dns::query::{CLASS_IN, TYPE_A};
use std::net::Ipv4Addr;

pub const HEADER: usize = 12;
pub const RECORD_HEADER: usize = 10;
pub const ADDRESS_LENGTH: usize = 4;

pub fn addresses(wire: &[u8]) -> Vec<Ipv4Addr> {
    read(wire).unwrap_or_default()
}

fn read(wire: &[u8]) -> Option<Vec<Ipv4Addr>> {
    if wire.len() < HEADER {
        return None;
    }
    let questions = u16::from_be_bytes([wire[4], wire[5]]);
    let answers = u16::from_be_bytes([wire[6], wire[7]]);

    let mut at = HEADER;
    for _ in 0..questions {
        at = name::skip(wire, at)?.checked_add(4)?;
        if at > wire.len() {
            return None;
        }
    }

    let mut found = Vec::new();
    for _ in 0..answers {
        at = name::skip(wire, at)?;
        if at + RECORD_HEADER > wire.len() {
            return None;
        }
        let kind = u16::from_be_bytes([wire[at], wire[at + 1]]);
        let class = u16::from_be_bytes([wire[at + 2], wire[at + 3]]);
        let length = u16::from_be_bytes([wire[at + 8], wire[at + 9]]) as usize;
        let data = at + RECORD_HEADER;
        let end = data.checked_add(length)?;
        if end > wire.len() {
            return None;
        }
        if kind == TYPE_A && class == CLASS_IN && length == ADDRESS_LENGTH {
            found.push(Ipv4Addr::new(
                wire[data],
                wire[data + 1],
                wire[data + 2],
                wire[data + 3],
            ));
        }
        at = end;
    }
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::addresses;
    use std::net::Ipv4Addr;

    fn reply(records: &[(u16, u16, &[u8])]) -> Vec<u8> {
        let mut wire = vec![0u8; 12];
        wire[6] = 0;
        wire[7] = records.len() as u8;
        wire[4] = 0;
        wire[5] = 1;
        wire.extend_from_slice(b"\x07example\x03org\x00");
        wire.extend_from_slice(&[0, 1, 0, 1]);
        for (kind, class, data) in records {
            wire.extend_from_slice(&[0xC0, 0x0C]);
            wire.extend_from_slice(&kind.to_be_bytes());
            wire.extend_from_slice(&class.to_be_bytes());
            wire.extend_from_slice(&[0, 0, 0x01, 0x2C]);
            wire.extend_from_slice(&(data.len() as u16).to_be_bytes());
            wire.extend_from_slice(data);
        }
        wire
    }

    #[test]
    fn an_address_record_gives_an_address() {
        let wire = reply(&[(1, 1, &[93, 184, 216, 34])]);
        assert_eq!(addresses(&wire), vec![Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[test]
    fn every_address_in_the_reply_is_read_and_in_order() {
        let wire = reply(&[(1, 1, &[10, 0, 0, 1]), (1, 1, &[10, 0, 0, 2])]);
        assert_eq!(
            addresses(&wire),
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
    }

    #[test]
    fn a_record_that_is_not_an_address_is_stepped_over_and_not_read_as_one() {
        let wire = reply(&[
            (5, 1, b"\x03www\x00"),
            (16, 1, b"\x04text"),
            (1, 1, &[8, 8, 8, 8]),
        ]);
        assert_eq!(addresses(&wire), vec![Ipv4Addr::new(8, 8, 8, 8)]);
    }

    #[test]
    fn an_address_record_from_another_class_is_not_an_address_of_ours() {
        let wire = reply(&[(1, 3, &[10, 0, 0, 1])]);
        assert!(addresses(&wire).is_empty());
    }

    #[test]
    fn a_record_whose_length_is_not_the_length_of_an_address_is_refused() {
        let wire = reply(&[(1, 1, &[10, 0, 0])]);
        assert!(addresses(&wire).is_empty());
    }

    #[test]
    fn a_reply_cut_short_gives_nothing_instead_of_reading_past_its_end() {
        let wire = reply(&[(1, 1, &[10, 0, 0, 1])]);
        for cut in 12..wire.len() {
            let _ = addresses(&wire[..cut]);
        }
        assert!(addresses(&wire[..wire.len() - 2]).is_empty());
        assert!(addresses(b"").is_empty());
        assert!(addresses(&[0u8; 11]).is_empty());
    }

    #[test]
    fn a_reply_that_claims_more_answers_than_it_carries_gives_nothing() {
        let mut wire = reply(&[(1, 1, &[10, 0, 0, 1])]);
        wire[7] = 40;
        assert!(addresses(&wire).is_empty());
    }

    #[test]
    fn a_reply_with_no_answers_gives_nothing() {
        let wire = reply(&[]);
        assert!(addresses(&wire).is_empty());
    }
}
