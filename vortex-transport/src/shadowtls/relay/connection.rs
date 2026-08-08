use crate::shadowtls::donor::allowlist::DonorAllowlist;
use crate::shadowtls::donor::target::DonorTarget;
use crate::shadowtls::relay::step::{ClientStep, DonorStep};
use crate::shadowtls::secret::keyring::Keyring;
use crate::shadowtls::session::keys;
use crate::shadowtls::session::role::Role;
use crate::shadowtls::session::stream::SealedStream;
use crate::shadowtls::switch::matcher::{self, Accepted};
use crate::tls::record::header::CONTENT_HANDSHAKE;
use crate::tls::record::scanner::{Record, RecordScanner, ScanStep};
use crate::tls::server_hello;
use crate::tls::server_hello::ServerRandom;
use crate::tls::server_name;
use std::sync::Arc;

pub struct Connection {
    keyring: Arc<Keyring>,
    allowlist: Arc<DonorAllowlist>,
    from_client: RecordScanner,
    from_donor: RecordScanner,
    server_random: Option<ServerRandom>,
    donor: Option<DonorTarget>,
    accepted: Option<Accepted>,
}

impl Connection {
    pub fn new(keyring: Arc<Keyring>, allowlist: Arc<DonorAllowlist>) -> Self {
        Connection {
            keyring,
            allowlist,
            from_client: RecordScanner::new(),
            from_donor: RecordScanner::new(),
            server_random: None,
            donor: None,
            accepted: None,
        }
    }

    pub fn donor(&self) -> Option<&DonorTarget> {
        self.donor.as_ref()
    }

    pub fn server_random(&self) -> Option<&ServerRandom> {
        self.server_random.as_ref()
    }

    pub fn session_id(&self) -> Option<&crate::shadowtls::switch::session_id::SessionId> {
        self.accepted.as_ref().map(|accepted| &accepted.session_id)
    }

    pub fn has_switched(&self) -> bool {
        self.accepted.is_some()
    }

    pub fn stream(&self, role: Role) -> Option<SealedStream> {
        let accepted = self.accepted.as_ref()?;
        let server_random = self.server_random.as_ref()?;
        Some(SealedStream::new(&keys::derive(
            &accepted.key,
            server_random,
            &accepted.session_id,
            role,
        )))
    }

    pub fn feed_client(&mut self, chunk: &[u8]) -> ClientStep {
        let mut step = ClientStep::default();
        if self.accepted.is_some() {
            step.trailing.extend_from_slice(chunk);
            return step;
        }

        self.from_client.push(chunk);
        if self.from_client.is_opaque() {
            step.opaque = true;
            step.forward = self.from_client.drain();
            return step;
        }

        loop {
            match self.from_client.next_record() {
                ScanStep::Record(record) => {
                    self.settle_donor(&record);
                    if let Some(accepted) = matcher::match_record(
                        &self.keyring,
                        self.server_random.as_ref(),
                        record.content_type(),
                        record.payload(),
                    ) {
                        self.accepted = Some(accepted);
                        step.switch = Some(accepted.session_id);
                        step.trailing = self.from_client.drain();
                        return step;
                    }
                    step.forward.extend_from_slice(record.bytes());
                }
                ScanStep::NeedMore => return step,
                ScanStep::NotTls => {
                    self.settle_fallback_donor();
                    step.opaque = true;
                    step.forward.extend_from_slice(&self.from_client.drain());
                    return step;
                }
            }
        }
    }

    pub fn feed_donor(&mut self, chunk: &[u8]) -> DonorStep {
        let mut step = DonorStep::default();
        self.from_donor.push(chunk);
        if self.from_donor.is_opaque() {
            step.opaque = true;
            step.forward = self.from_donor.drain();
            return step;
        }

        loop {
            match self.from_donor.next_record() {
                ScanStep::Record(record) => {
                    self.remember_server_random(&record);
                    step.forward.extend_from_slice(record.bytes());
                }
                ScanStep::NeedMore => return step,
                ScanStep::NotTls => {
                    step.opaque = true;
                    step.forward.extend_from_slice(&self.from_donor.drain());
                    return step;
                }
            }
        }
    }

    fn remember_server_random(&mut self, record: &Record) {
        if self.server_random.is_some() || record.content_type() != CONTENT_HANDSHAKE {
            return;
        }
        self.server_random = server_hello::random(record.payload());
    }

    fn settle_donor(&mut self, record: &Record) {
        if self.donor.is_some() {
            return;
        }
        let requested = match record.content_type() {
            CONTENT_HANDSHAKE => server_name::from_client_hello(record.payload()),
            _ => None,
        };
        self.donor = Some(self.allowlist.resolve(requested).clone());
    }

    fn settle_fallback_donor(&mut self) {
        if self.donor.is_none() {
            self.donor = Some(self.allowlist.fallback().clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::random::fixed_random::FixedRandom;
    use crate::shadowtls::guard::ShadowTls;
    use crate::shadowtls::relay::connection::Connection;
    use crate::shadowtls::session::role::Role;
    use crate::shadowtls::switch::session_id::SessionId;
    use crate::tls::client_hello::testing::{client_hello, tls_record};
    use crate::tls::server_hello::testing::server_hello_record;

    const DONOR_RANDOM: [u8; 32] = [0x77; 32];

    fn guard() -> ShadowTls {
        ShadowTls::new(b"testpass", b"")
    }

    fn session_id() -> SessionId {
        SessionId::from_bytes([0x02; 16])
    }

    fn server_name_extension(host: &[u8]) -> Vec<u8> {
        let mut entry = vec![0x00];
        entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        entry.extend_from_slice(host);

        let mut body = (entry.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&entry);

        let mut extension = vec![0x00, 0x00];
        extension.extend_from_slice(&(body.len() as u16).to_be_bytes());
        extension.extend_from_slice(&body);
        extension
    }

    fn hello_for(host: &[u8]) -> Vec<u8> {
        tls_record(&client_hello(&[0xAB; 32], &server_name_extension(host)))
    }

    fn record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![content_type, 0x03, 0x03];
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn switch_record(guard: &ShadowTls, server_random: &[u8; 32]) -> Vec<u8> {
        let random = FixedRandom::new(vec![]).with_filler(0x00);
        guard
            .seal_switch(server_random, &session_id(), &random)
            .unwrap()
    }

    fn handshaken(guard: &ShadowTls) -> Connection {
        let mut connection = guard.connection();
        connection.feed_client(&hello_for(b"www.google.com"));
        connection.feed_donor(&server_hello_record(&DONOR_RANDOM));
        connection
    }

    #[test]
    fn the_donor_is_the_name_the_client_asked_for() {
        let guard = guard();
        let mut connection = guard.connection();
        connection.feed_client(&hello_for(b"www.apple.com"));
        assert_eq!(connection.donor().unwrap().host, "www.apple.com");
    }

    #[test]
    fn a_name_outside_the_allowlist_never_becomes_a_destination() {
        let guard = guard();
        let mut connection = guard.connection();
        connection.feed_client(&hello_for(b"attacker.example"));
        assert_eq!(connection.donor().unwrap(), guard.donors().fallback());
    }

    #[test]
    fn the_donor_waits_for_a_whole_client_hello() {
        let guard = guard();
        let mut connection = guard.connection();
        let hello = hello_for(b"www.apple.com");
        connection.feed_client(&hello[..7]);
        assert_eq!(connection.donor(), None);
        connection.feed_client(&hello[7..]);
        assert_eq!(connection.donor().unwrap().host, "www.apple.com");
    }

    #[test]
    fn the_handshake_is_relayed_to_the_donor_byte_for_byte() {
        let guard = guard();
        let mut connection = guard.connection();
        let hello = hello_for(b"www.google.com");
        let mut forwarded = Vec::new();
        for byte in hello.iter() {
            forwarded.extend_from_slice(&connection.feed_client(&[*byte]).forward);
        }
        assert_eq!(forwarded, hello);
    }

    #[test]
    fn a_stream_that_is_not_tls_is_handed_back_whole() {
        let guard = guard();
        let mut connection = guard.connection();
        let step = connection.feed_client(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(step.opaque);
        assert_eq!(step.forward, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec());
        assert_eq!(connection.donor().unwrap(), guard.donors().fallback());
        let more = connection.feed_client(b"tail");
        assert!(more.opaque);
        assert_eq!(more.forward, b"tail".to_vec());
    }

    #[test]
    fn a_switch_record_is_recognised_and_never_reaches_the_donor() {
        let guard = guard();
        let mut connection = handshaken(&guard);
        let step = connection.feed_client(&switch_record(&guard, &DONOR_RANDOM));
        assert_eq!(step.switch, Some(session_id()));
        assert!(step.forward.is_empty());
        assert!(connection.has_switched());
    }

    #[test]
    fn bytes_after_the_switch_are_handed_back_as_data() {
        let guard = guard();
        let mut connection = handshaken(&guard);
        let mut chunk = switch_record(&guard, &DONOR_RANDOM);
        chunk.extend_from_slice(b"DATA-AFTER-SWITCH");
        let step = connection.feed_client(&chunk);
        assert_eq!(step.trailing, b"DATA-AFTER-SWITCH".to_vec());
        let next = connection.feed_client(b"MORE");
        assert_eq!(next.trailing, b"MORE".to_vec());
        assert!(next.forward.is_empty());
    }

    #[test]
    fn a_switch_split_across_segments_is_still_recognised() {
        let guard = guard();
        let mut connection = handshaken(&guard);
        let switch = switch_record(&guard, &DONOR_RANDOM);
        let mut seen = None;
        for byte in switch.iter() {
            let step = connection.feed_client(&[*byte]);
            assert!(step.forward.is_empty());
            if step.switch.is_some() {
                seen = step.switch;
            }
        }
        assert_eq!(seen, Some(session_id()));
    }

    #[test]
    fn a_switch_before_the_donor_answered_is_relayed_like_any_record() {
        let guard = guard();
        let mut connection = guard.connection();
        connection.feed_client(&hello_for(b"www.google.com"));
        let switch = switch_record(&guard, &DONOR_RANDOM);
        let step = connection.feed_client(&switch);
        assert_eq!(step.switch, None);
        assert_eq!(step.forward, switch);
    }

    #[test]
    fn a_switch_captured_from_another_connection_does_not_replay() {
        let guard = guard();
        let captured = switch_record(&guard, &DONOR_RANDOM);

        let mut connection = guard.connection();
        connection.feed_client(&hello_for(b"www.google.com"));
        connection.feed_donor(&server_hello_record(&[0x88; 32]));
        let step = connection.feed_client(&captured);
        assert_eq!(step.switch, None);
        assert_eq!(step.forward, captured);
    }

    #[test]
    fn the_donor_answer_is_relayed_whole_and_leaves_its_random_behind() {
        let guard = guard();
        let mut connection = guard.connection();
        connection.feed_client(&hello_for(b"www.google.com"));
        let hello = server_hello_record(&DONOR_RANDOM);
        let mut forwarded = Vec::new();
        for byte in hello.iter() {
            forwarded.extend_from_slice(&connection.feed_donor(&[*byte]).forward);
        }
        assert_eq!(forwarded, hello);
        assert_eq!(connection.server_random(), Some(&DONOR_RANDOM));
    }

    #[test]
    fn only_the_first_server_hello_sets_the_random() {
        let guard = guard();
        let mut connection = handshaken(&guard);
        connection.feed_donor(&server_hello_record(&[0x99; 32]));
        assert_eq!(connection.server_random(), Some(&DONOR_RANDOM));
    }

    #[test]
    fn an_application_record_from_the_donor_never_sets_the_random() {
        let guard = guard();
        let mut connection = guard.connection();
        connection.feed_client(&hello_for(b"www.google.com"));
        connection.feed_donor(&record(0x17, &[0x02; 64]));
        assert_eq!(connection.server_random(), None);
    }

    #[test]
    fn the_stream_after_the_switch_talks_to_the_client_that_sealed_it() {
        let guard = guard();
        let mut connection = handshaken(&guard);
        connection.feed_client(&switch_record(&guard, &DONOR_RANDOM));

        let mut server = connection.stream(Role::Server).unwrap();
        let mut client = guard
            .stream(&DONOR_RANDOM, &session_id(), Role::Client)
            .unwrap();
        let frame = server.wrap(b"hello");
        assert_eq!(client.unwrap(&frame), Some(b"hello".to_vec()));
    }

    #[test]
    fn there_is_no_stream_before_the_switch() {
        let guard = guard();
        let mut connection = handshaken(&guard);
        assert!(connection.stream(Role::Server).is_none());
        connection.feed_client(&switch_record(&guard, &DONOR_RANDOM));
        assert!(connection.stream(Role::Server).is_some());
    }

    #[test]
    fn a_rotated_password_still_switches_and_keys_the_stream() {
        let previous = ShadowTls::new(b"old", b"");
        let rotated = ShadowTls::new(b"new", b"old");
        let mut connection = handshaken(&rotated);
        let step = connection.feed_client(&switch_record(&previous, &DONOR_RANDOM));
        assert_eq!(step.switch, Some(session_id()));

        let mut server = connection.stream(Role::Server).unwrap();
        let mut client = previous
            .stream(&DONOR_RANDOM, &session_id(), Role::Client)
            .unwrap();
        let frame = server.wrap(b"hello");
        assert_eq!(client.unwrap(&frame), Some(b"hello".to_vec()));
    }
}
