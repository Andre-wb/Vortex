use crate::wire::PUBKEY_HEX_LEN;

pub fn normalize_pubkey(candidate: Option<&str>) -> Option<String> {
    let value = candidate?;
    if value.chars().count() != PUBKEY_HEX_LEN {
        return None;
    }
    if !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return None;
    }
    Some(value.to_string())
}
