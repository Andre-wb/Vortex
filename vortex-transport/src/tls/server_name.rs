use crate::tls::byte_slice::{be_uint, clamped};
use crate::tls::client_hello;

pub const EXTENSION_SERVER_NAME: usize = 0x0000;
pub const NAME_TYPE_HOST: u8 = 0x00;
pub const MAX_HOST_LEN: usize = 253;

pub fn from_client_hello(data: &[u8]) -> Option<&str> {
    let hello = client_hello::parse(data)?;
    hello
        .extensions()
        .find(|extension| extension.kind == EXTENSION_SERVER_NAME)
        .and_then(|extension| host_name(extension.body))
}

pub fn host_name(body: &[u8]) -> Option<&str> {
    let list_len = be_uint(body, 0, 2);
    let end = body.len().min(2 + list_len);
    let mut pos = 2usize;
    while pos + 3 <= end {
        let name_type = body[pos];
        let name_len = be_uint(body, pos + 1, 2);
        let name = clamped(body, pos + 3, name_len);
        pos += 3 + name_len;
        if name_type != NAME_TYPE_HOST || name.len() != name_len {
            continue;
        }
        if let Some(host) = plausible_host(name) {
            return Some(host);
        }
    }
    None
}

pub fn plausible_host(name: &[u8]) -> Option<&str> {
    if name.is_empty() || name.len() > MAX_HOST_LEN {
        return None;
    }
    let acceptable = name
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'));
    if !acceptable {
        return None;
    }
    std::str::from_utf8(name).ok()
}

#[cfg(test)]
mod tests {
    use super::{from_client_hello, host_name, EXTENSION_SERVER_NAME};
    use crate::tls::client_hello::testing::{client_hello, tls_record};

    fn server_name_extension(host: &[u8]) -> Vec<u8> {
        let mut entry = vec![0x00];
        entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        entry.extend_from_slice(host);

        let mut body = (entry.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&entry);

        let mut extension = (EXTENSION_SERVER_NAME as u16).to_be_bytes().to_vec();
        extension.extend_from_slice(&(body.len() as u16).to_be_bytes());
        extension.extend_from_slice(&body);
        extension
    }

    #[test]
    fn reads_the_host_from_a_client_hello() {
        let hello = client_hello(&[0xAB; 32], &server_name_extension(b"www.google.com"));
        assert_eq!(
            from_client_hello(&tls_record(&hello)),
            Some("www.google.com")
        );
    }

    #[test]
    fn a_hello_without_the_extension_carries_no_host() {
        let hello = client_hello(&[0xAB; 32], &[]);
        assert_eq!(from_client_hello(&tls_record(&hello)), None);
    }

    #[test]
    fn a_host_with_bytes_outside_a_hostname_is_refused() {
        assert_eq!(host_name(&server_name_extension(b"a b.com")[4..]), None);
        assert_eq!(
            host_name(&server_name_extension("гугл.рф".as_bytes())[4..]),
            None
        );
        assert_eq!(
            host_name(&server_name_extension(b"host\r\n.com")[4..]),
            None
        );
    }

    #[test]
    fn an_empty_or_overlong_host_is_refused() {
        assert_eq!(host_name(&server_name_extension(b"")[4..]), None);
        let long = vec![b'a'; 254];
        assert_eq!(host_name(&server_name_extension(&long)[4..]), None);
    }

    #[test]
    fn a_truncated_entry_is_refused() {
        let mut body = server_name_extension(b"www.apple.com")[4..].to_vec();
        body.truncate(body.len() - 3);
        assert_eq!(host_name(&body), None);
    }

    #[test]
    fn a_non_host_name_type_is_skipped() {
        let mut body = vec![0x00, 0x00];
        body.extend_from_slice(&[0x01, 0x00, 0x03]);
        body.extend_from_slice(b"abc");
        let list_len = (body.len() - 2) as u16;
        body[0..2].copy_from_slice(&list_len.to_be_bytes());
        assert_eq!(host_name(&body), None);
    }
}
