use crate::entropy::crc32;

pub const HEADER: [u8; 10] = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF];
pub const MAX_STORED_BLOCK: usize = 65_535;
pub const TRAILER: usize = 8;
pub const BLOCK_HEADER: usize = 5;

pub fn wrap(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER.len() + payload.len() + TRAILER + BLOCK_HEADER);
    out.extend_from_slice(&HEADER);
    for (block, is_last) in blocks(payload) {
        out.push(if is_last { 0x01 } else { 0x00 });
        out.extend_from_slice(&(block.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&crc32::of(payload).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out
}

pub fn unwrap(envelope: &[u8]) -> Option<Vec<u8>> {
    if envelope.len() < HEADER.len() + TRAILER {
        return None;
    }
    if envelope[..2] != HEADER[..2] {
        return None;
    }
    let body = &envelope[HEADER.len()..envelope.len() - TRAILER];
    let mut payload = Vec::with_capacity(body.len());
    let mut at = 0;

    loop {
        if at + BLOCK_HEADER > body.len() {
            return None;
        }
        let marker = body[at];
        if marker & 0x06 != 0 {
            return None;
        }
        let length = u16::from_le_bytes([body[at + 1], body[at + 2]]) as usize;
        let checked = u16::from_le_bytes([body[at + 3], body[at + 4]]);
        if checked != !(length as u16) {
            return None;
        }
        let start = at + BLOCK_HEADER;
        let end = start.checked_add(length)?;
        if end > body.len() {
            return None;
        }
        payload.extend_from_slice(&body[start..end]);
        at = end;
        if marker & 0x01 == 1 {
            break;
        }
    }

    if at != body.len() {
        return None;
    }

    let trailer = &envelope[envelope.len() - TRAILER..];
    let stated_sum = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let stated_size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    if stated_size as usize != payload.len() || stated_sum != crc32::of(&payload) {
        return None;
    }
    Some(payload)
}

fn blocks(payload: &[u8]) -> Vec<(&[u8], bool)> {
    if payload.is_empty() {
        return vec![(payload, true)];
    }
    let chunks: Vec<&[u8]> = payload.chunks(MAX_STORED_BLOCK).collect();
    let last = chunks.len() - 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| (chunk, index == last))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{unwrap, wrap, HEADER, MAX_STORED_BLOCK};

    #[test]
    fn what_was_wrapped_comes_back_exactly() {
        for payload in [
            b"".to_vec(),
            b"hello".to_vec(),
            vec![0xABu8; 1024],
            vec![0x00u8; MAX_STORED_BLOCK],
            vec![0x7Fu8; MAX_STORED_BLOCK + 1],
            vec![0x11u8; MAX_STORED_BLOCK * 3 + 17],
        ] {
            assert_eq!(
                unwrap(&wrap(&payload)),
                Some(payload.clone()),
                "длина {}",
                payload.len()
            );
        }
    }

    #[test]
    fn the_envelope_looks_like_a_compressed_page_to_whoever_reads_its_first_bytes() {
        let envelope = wrap(b"encrypted");
        assert_eq!(&envelope[..HEADER.len()], &HEADER);
        assert_eq!(&envelope[..2], &[0x1F, 0x8B]);
    }

    #[test]
    fn a_payload_larger_than_one_block_is_written_as_several_and_only_the_last_is_final() {
        let payload = vec![0x22u8; MAX_STORED_BLOCK * 2 + 5];
        let envelope = wrap(&payload);
        assert_eq!(envelope[HEADER.len()], 0x00);
        assert_eq!(unwrap(&envelope), Some(payload));
    }

    #[test]
    fn what_is_not_an_envelope_is_refused_rather_than_returned_as_it_is() {
        assert_eq!(unwrap(b""), None);
        assert_eq!(unwrap(b"plain text that is long enough to measure"), None);
        assert_eq!(unwrap(&[0x1F, 0x8B]), None);
    }

    #[test]
    fn an_envelope_whose_length_was_tampered_with_is_refused() {
        let mut envelope = wrap(b"hello world");
        envelope[HEADER.len() + 1] = 0xFF;
        assert_eq!(unwrap(&envelope), None);
    }

    #[test]
    fn an_envelope_whose_payload_was_tampered_with_is_refused() {
        let mut envelope = wrap(b"hello world");
        let at = HEADER.len() + 5;
        envelope[at] ^= 0xFF;
        assert_eq!(unwrap(&envelope), None);
    }

    #[test]
    fn an_envelope_with_bytes_appended_after_the_last_block_is_refused() {
        let mut envelope = wrap(b"hello world");
        let trailer: Vec<u8> = envelope.split_off(envelope.len() - 8);
        envelope.extend_from_slice(b"extra");
        envelope.extend_from_slice(&trailer);
        assert_eq!(unwrap(&envelope), None);
    }

    #[test]
    fn an_envelope_that_never_marks_a_last_block_ends_instead_of_looping() {
        let mut envelope = wrap(b"hello world");
        envelope[HEADER.len()] = 0x00;
        assert_eq!(unwrap(&envelope), None);
    }
}
