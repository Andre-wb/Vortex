use vortex_net::random::FixedRandom;
use vortex_net::stealth;

const NETWORK_KEY: &[u8] = b"shared-vortex-network-key";

#[test]
fn a_sealed_payload_opens_back_to_the_original() {
    let payload = br#"{"name":"alice","port":9000}"#;
    let nonce = [3u8; 8];
    let sealed = stealth::seal(payload, &nonce, NETWORK_KEY);
    assert_eq!(&sealed[..8], &nonce);
    let opened = stealth::open(&sealed, NETWORK_KEY).unwrap();
    assert_eq!(opened, payload);
}

#[test]
fn the_random_nonce_travels_in_the_clear_and_still_round_trips() {
    let payload = b"discovery-beacon";
    let random = FixedRandom::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let sealed = stealth::seal_with(payload, &random, NETWORK_KEY);
    assert_eq!(&sealed[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(stealth::open(&sealed, NETWORK_KEY).unwrap(), payload);
}

#[test]
fn an_envelope_shorter_than_the_minimum_is_rejected() {
    assert!(stealth::open(b"short", NETWORK_KEY).is_none());
    assert!(stealth::open(&[0u8; 8], NETWORK_KEY).is_none());
    assert!(stealth::open(&[0u8; 9], NETWORK_KEY).is_some());
}

#[test]
fn a_different_network_key_does_not_recover_the_payload() {
    let payload = b"secret-beacon";
    let nonce = [9u8; 8];
    let sealed = stealth::seal(payload, &nonce, NETWORK_KEY);
    let opened = stealth::open(&sealed, b"a-completely-different-key").unwrap();
    assert_ne!(opened, payload);
}
