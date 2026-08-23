use vortex_net::wire;

#[test]
fn a_full_frame_round_trips_through_encode_and_decode() {
    let pubkey = "bb".repeat(32);
    let frame = wire::encode("workstation", 9000, Some(&pubkey));
    let decoded = wire::decode(&frame, "192.168.1.9", 8000).unwrap();
    assert_eq!(decoded.name, "workstation");
    assert_eq!(decoded.port, 9000);
    assert_eq!(decoded.pubkey, Some(pubkey));
}

#[test]
fn a_missing_name_falls_back_to_the_source_address() {
    let decoded = wire::decode(br#"{"port":9000}"#, "10.0.0.7", 8000).unwrap();
    assert_eq!(decoded.name, "10.0.0.7");
}

#[test]
fn a_missing_port_falls_back_to_the_signaling_port() {
    let decoded = wire::decode(br#"{"name":"n"}"#, "10.0.0.7", 8123).unwrap();
    assert_eq!(decoded.port, 8123);
}

#[test]
fn a_name_longer_than_the_cap_is_truncated_to_sixty_four_characters() {
    let long = "x".repeat(200);
    let frame = format!(r#"{{"name":"{long}","port":9000}}"#);
    let decoded = wire::decode(frame.as_bytes(), "10.0.0.7", 8000).unwrap();
    assert_eq!(decoded.name.chars().count(), 64);
}

#[test]
fn a_pubkey_of_the_wrong_length_is_dropped_without_dropping_the_peer() {
    let decoded = wire::decode(
        br#"{"name":"n","port":9000,"pubkey":"abcd"}"#,
        "10.0.0.7",
        8000,
    )
    .unwrap();
    assert_eq!(decoded.pubkey, None);
}

#[test]
fn a_pubkey_that_is_not_hex_is_dropped_without_dropping_the_peer() {
    let not_hex = "z".repeat(64);
    let frame = format!(r#"{{"name":"n","port":9000,"pubkey":"{not_hex}"}}"#);
    let decoded = wire::decode(frame.as_bytes(), "10.0.0.7", 8000).unwrap();
    assert_eq!(decoded.pubkey, None);
}

#[test]
fn a_port_out_of_range_drops_the_whole_packet() {
    assert!(wire::decode(br#"{"name":"n","port":0}"#, "10.0.0.7", 8000).is_none());
    assert!(wire::decode(br#"{"name":"n","port":70000}"#, "10.0.0.7", 8000).is_none());
}

#[test]
fn a_numeric_string_port_is_accepted_like_python_int() {
    let decoded = wire::decode(br#"{"name":"n","port":"9000"}"#, "10.0.0.7", 8000).unwrap();
    assert_eq!(decoded.port, 9000);
}

#[test]
fn a_non_object_and_broken_json_are_dropped() {
    assert!(wire::decode(b"[1,2,3]", "10.0.0.7", 8000).is_none());
    assert!(wire::decode(b"not json", "10.0.0.7", 8000).is_none());
    assert!(wire::decode(b"", "10.0.0.7", 8000).is_none());
}
