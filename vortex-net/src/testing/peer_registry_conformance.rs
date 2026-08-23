use std::sync::Arc;

use crate::ports::peer_registry::PeerRegistry;
use crate::registry::service::PeerRegistryService;

const TIMEOUT: f64 = 30.0;

fn service(store: Arc<dyn PeerRegistry>) -> PeerRegistryService {
    PeerRegistryService::new(store, TIMEOUT)
}

fn key(tag: &str) -> String {
    format!("{tag}{}", "0".repeat(64 - tag.len()))
}

fn addresses(peers: &PeerRegistryService, now: f64) -> Vec<String> {
    peers
        .alive(now)
        .unwrap()
        .iter()
        .map(|known| known.address().written().to_owned())
        .collect()
}

fn rooms_of(peers: &PeerRegistryService, now: f64, address: &str) -> Option<String> {
    peers
        .rooms_of_the_living(now)
        .unwrap()
        .into_iter()
        .find(|(known, _)| known.address().written() == address)
        .map(|(_, document)| document)
}

pub fn a_heard_peer_is_found_again(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    assert!(peers
        .heard("10.0.0.1", "one", 8000, None, 1000.0)
        .unwrap()
        .unwrap());
    let found = peers.find("10.0.0.1").unwrap().unwrap().unwrap();
    assert_eq!(found.name().written(), "one");
    assert_eq!(found.port(), 8000);
    assert_eq!(found.last_seen(), 1000.0);
    assert!(!found.encrypted());
}

pub fn an_unknown_address_names_no_peer(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    assert!(peers.find("10.0.0.99").unwrap().unwrap().is_none());
}

pub fn hearing_a_known_peer_again_is_not_news(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    assert!(peers
        .heard("10.0.0.2", "two", 8000, None, 1000.0)
        .unwrap()
        .unwrap());
    assert!(!peers
        .heard("10.0.0.2", "two", 8001, None, 1005.0)
        .unwrap()
        .unwrap());
    let found = peers.find("10.0.0.2").unwrap().unwrap().unwrap();
    assert_eq!(found.port(), 8001);
    assert_eq!(found.last_seen(), 1005.0);
}

pub fn a_key_survives_a_silent_refresh(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    peers
        .heard("10.0.0.3", "three", 8000, Some(&key("aa")), 1000.0)
        .unwrap()
        .unwrap();
    peers
        .heard("10.0.0.3", "three", 8000, None, 1001.0)
        .unwrap()
        .unwrap();
    let found = peers.find("10.0.0.3").unwrap().unwrap().unwrap();
    assert_eq!(found.pubkey().unwrap().written(), key("aa"));
    assert!(found.encrypted());
}

pub fn a_key_of_the_wrong_shape_is_not_kept(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    peers
        .heard("10.0.0.4", "four", 8000, Some("too-short"), 1000.0)
        .unwrap()
        .unwrap();
    let found = peers.find("10.0.0.4").unwrap().unwrap().unwrap();
    assert!(found.pubkey().is_none());
}

pub fn only_the_living_are_told(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    peers
        .heard("10.0.1.1", "old", 8000, None, 1000.0)
        .unwrap()
        .unwrap();
    peers
        .heard("10.0.1.2", "new", 8000, None, 1020.0)
        .unwrap()
        .unwrap();
    let named = addresses(&peers, 1031.0);
    assert!(!named.contains(&"10.0.1.1".to_owned()));
    assert!(named.contains(&"10.0.1.2".to_owned()));
}

pub fn a_peer_is_alive_until_the_timeout_and_not_at_it(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    peers
        .heard("10.0.2.1", "edge", 8000, None, 1000.0)
        .unwrap()
        .unwrap();
    assert!(addresses(&peers, 1000.0 + TIMEOUT - 0.001).contains(&"10.0.2.1".to_owned()));
    assert!(!addresses(&peers, 1000.0 + TIMEOUT).contains(&"10.0.2.1".to_owned()));
    assert!(peers.find("10.0.2.1").unwrap().unwrap().is_some());
}

pub fn forgetting_the_dead_removes_them_and_their_rooms(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    peers
        .heard("10.0.3.1", "gone", 8000, None, 1000.0)
        .unwrap()
        .unwrap();
    peers
        .set_rooms("10.0.3.1", "[{\"id\":1}]")
        .unwrap()
        .unwrap();
    assert!(peers.forget_dead(1000.0 + TIMEOUT).unwrap() >= 1);
    assert!(peers.find("10.0.3.1").unwrap().unwrap().is_none());
    assert!(rooms_of(&peers, 1000.0, "10.0.3.1").is_none());
}

pub fn forgetting_the_dead_keeps_the_living(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    peers
        .heard("10.0.4.1", "here", 8000, None, 1000.0)
        .unwrap()
        .unwrap();
    peers.forget_dead(1001.0).unwrap();
    assert!(peers.find("10.0.4.1").unwrap().unwrap().is_some());
}

pub fn rooms_are_told_only_for_living_peers(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    peers
        .heard("10.0.5.1", "live", 8000, None, 1000.0)
        .unwrap()
        .unwrap();
    peers
        .heard("10.0.5.2", "dead", 8000, None, 900.0)
        .unwrap()
        .unwrap();
    peers
        .set_rooms("10.0.5.1", "[{\"id\":1}]")
        .unwrap()
        .unwrap();
    peers
        .set_rooms("10.0.5.2", "[{\"id\":2}]")
        .unwrap()
        .unwrap();
    assert_eq!(
        rooms_of(&peers, 1001.0, "10.0.5.1"),
        Some("[{\"id\":1}]".to_owned())
    );
    assert!(rooms_of(&peers, 1001.0, "10.0.5.2").is_none());
}

pub fn a_peer_without_rooms_is_not_told(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    peers
        .heard("10.0.6.1", "quiet", 8000, None, 1000.0)
        .unwrap()
        .unwrap();
    assert!(rooms_of(&peers, 1001.0, "10.0.6.1").is_none());
}

pub fn a_later_room_list_replaces_the_earlier_one(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    peers
        .heard("10.0.7.1", "busy", 8000, None, 1000.0)
        .unwrap()
        .unwrap();
    peers
        .set_rooms("10.0.7.1", "[{\"id\":1}]")
        .unwrap()
        .unwrap();
    peers
        .set_rooms("10.0.7.1", "[{\"id\":2}]")
        .unwrap()
        .unwrap();
    assert_eq!(
        rooms_of(&peers, 1001.0, "10.0.7.1"),
        Some("[{\"id\":2}]".to_owned())
    );
}

pub fn peers_do_not_shadow_each_other(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    let before = peers.count().unwrap();
    peers
        .heard("10.0.8.1", "left", 8000, None, 1000.0)
        .unwrap()
        .unwrap();
    peers
        .heard("10.0.8.2", "right", 8001, None, 1000.0)
        .unwrap()
        .unwrap();
    assert_eq!(peers.count().unwrap(), before + 2);
    assert_eq!(
        peers.find("10.0.8.1").unwrap().unwrap().unwrap().port(),
        8000
    );
}

pub fn an_address_that_is_not_an_address_is_refused(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    assert!(peers
        .heard("example.com", "name", 8000, None, 1000.0)
        .is_err());
    assert!(peers.find("not-an-ip").is_err());
    assert!(peers.set_rooms("not-an-ip", "[]").is_err());
}

pub fn a_port_outside_the_range_is_refused(store: Arc<dyn PeerRegistry>) {
    let peers = service(store);
    assert!(peers.heard("10.0.9.1", "name", 0, None, 1000.0).is_err());
}
