use serde::Serialize;

#[derive(Serialize)]
pub struct Outgoing<'a> {
    pub name: &'a str,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub name: String,
    pub port: u16,
    pub pubkey: Option<String>,
}
