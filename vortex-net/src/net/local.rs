pub fn is_loopback(ip: &str) -> bool {
    ip.starts_with("127.")
}
