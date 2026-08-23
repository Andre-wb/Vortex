use crate::wire::payload::Outgoing;

pub fn encode(name: &str, port: u16, pubkey: Option<&str>) -> Vec<u8> {
    let outgoing = Outgoing { name, port, pubkey };
    serde_json::to_vec(&outgoing).expect("сериализация discovery-конверта не может отказать")
}
