use crate::tls::record::header::{self, RECORD_HEADER_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    bytes: Vec<u8>,
}

impl Record {
    pub fn content_type(&self) -> u8 {
        self.bytes[0]
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[RECORD_HEADER_LEN..]
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStep {
    Record(Record),
    NeedMore,
    NotTls,
}

#[derive(Debug, Default)]
pub struct RecordScanner {
    buffer: Vec<u8>,
    opaque: bool,
}

impl RecordScanner {
    pub fn new() -> Self {
        RecordScanner::default()
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    pub fn is_opaque(&self) -> bool {
        self.opaque
    }

    pub fn drain(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }

    pub fn next_record(&mut self) -> ScanStep {
        if self.opaque {
            return ScanStep::NotTls;
        }
        if self.buffer.len() < RECORD_HEADER_LEN {
            return ScanStep::NeedMore;
        }
        let Some(parsed) = header::parse(&self.buffer) else {
            self.opaque = true;
            return ScanStep::NotTls;
        };
        let total = RECORD_HEADER_LEN + parsed.payload_len;
        if self.buffer.len() < total {
            return ScanStep::NeedMore;
        }
        let rest = self.buffer.split_off(total);
        let bytes = std::mem::replace(&mut self.buffer, rest);
        ScanStep::Record(Record { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::{RecordScanner, ScanStep};

    fn record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![content_type, 0x03, 0x03];
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn take(scanner: &mut RecordScanner) -> Option<Vec<u8>> {
        match scanner.next_record() {
            ScanStep::Record(found) => Some(found.into_bytes()),
            _ => None,
        }
    }

    #[test]
    fn hands_out_whole_records_in_order() {
        let mut scanner = RecordScanner::new();
        let first = record(0x16, b"hello");
        let second = record(0x17, b"data");
        scanner.push(&first);
        scanner.push(&second);
        assert_eq!(take(&mut scanner), Some(first));
        assert_eq!(take(&mut scanner), Some(second));
        assert_eq!(scanner.next_record(), ScanStep::NeedMore);
    }

    #[test]
    fn a_record_split_across_chunks_is_reassembled() {
        let whole = record(0x17, b"payload-of-a-record");
        let mut scanner = RecordScanner::new();
        for byte in whole.iter() {
            assert_eq!(scanner.next_record(), ScanStep::NeedMore);
            scanner.push(&[*byte]);
        }
        assert_eq!(take(&mut scanner), Some(whole));
    }

    #[test]
    fn the_payload_is_offered_without_the_header() {
        let mut scanner = RecordScanner::new();
        scanner.push(&record(0x17, b"body"));
        match scanner.next_record() {
            ScanStep::Record(found) => {
                assert_eq!(found.payload(), b"body");
                assert_eq!(found.content_type(), 0x17);
            }
            other => panic!("ожидалась запись, получено {other:?}"),
        }
    }

    #[test]
    fn a_foreign_header_latches_the_scanner_open() {
        let mut scanner = RecordScanner::new();
        scanner.push(b"GET / HTTP/1.1\r\n");
        assert_eq!(scanner.next_record(), ScanStep::NotTls);
        assert!(scanner.is_opaque());
        scanner.push(&record(0x17, b"body"));
        assert_eq!(scanner.next_record(), ScanStep::NotTls);
        assert_eq!(scanner.drain().len(), 16 + 9);
    }

    #[test]
    fn draining_gives_back_everything_not_yet_parsed() {
        let mut scanner = RecordScanner::new();
        scanner.push(b"GET /");
        assert_eq!(scanner.next_record(), ScanStep::NotTls);
        assert_eq!(scanner.drain(), b"GET /".to_vec());
        assert_eq!(scanner.drain(), Vec::<u8>::new());
    }
}
