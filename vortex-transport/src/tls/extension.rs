use crate::tls::byte_slice::{be_uint, clamped};

pub const EXTENSION_HEADER_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension<'a> {
    pub kind: usize,
    pub body: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct Extensions<'a> {
    buffer: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Extensions<'a> {
    pub fn new(buffer: &'a [u8], pos: usize, end: usize) -> Self {
        Extensions { buffer, pos, end }
    }
}

impl<'a> Iterator for Extensions<'a> {
    type Item = Extension<'a>;

    fn next(&mut self) -> Option<Extension<'a>> {
        if self.pos + EXTENSION_HEADER_LEN > self.end {
            return None;
        }
        let kind = be_uint(self.buffer, self.pos, 2);
        let len = be_uint(self.buffer, self.pos + 2, 2);
        let body = clamped(self.buffer, self.pos + EXTENSION_HEADER_LEN, len);
        self.pos += EXTENSION_HEADER_LEN + len;
        Some(Extension { kind, body })
    }
}

#[cfg(test)]
mod tests {
    use super::{Extension, Extensions};

    fn encoded(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn walks_every_extension_in_order() {
        let mut buffer = encoded(0x0000, b"one");
        buffer.extend_from_slice(&encoded(0x0033, b"two"));
        let end = buffer.len();
        let found: Vec<Extension> = Extensions::new(&buffer, 0, end).collect();
        assert_eq!(
            found,
            vec![
                Extension {
                    kind: 0x0000,
                    body: b"one"
                },
                Extension {
                    kind: 0x0033,
                    body: b"two"
                },
            ]
        );
    }

    #[test]
    fn a_truncated_body_yields_what_exists_and_stops() {
        let mut buffer = 0x0033u16.to_be_bytes().to_vec();
        buffer.extend_from_slice(&64u16.to_be_bytes());
        buffer.extend_from_slice(b"short");
        let end = buffer.len();
        let found: Vec<Extension> = Extensions::new(&buffer, 0, end).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].body, b"short");
    }

    #[test]
    fn nothing_is_read_past_the_declared_end() {
        let mut buffer = encoded(0x0000, b"one");
        let end = buffer.len();
        buffer.extend_from_slice(&encoded(0x0033, b"two"));
        let found: Vec<Extension> = Extensions::new(&buffer, 0, end).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, 0x0000);
    }
}
