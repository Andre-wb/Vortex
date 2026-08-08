use crate::naive::caddy::site::CaddySite;
use crate::naive::caddy::token::quoted;

pub fn render(site: &CaddySite) -> String {
    format!(
        r#"{{
    order forward_proxy before file_server
    servers {{
        protocols h1 h2
    }}
}}

:{port} {{
    tls {email} {{
        protocols tls1.2 tls1.3
        curves x25519 secp256r1 secp384r1
    }}

    forward_proxy {{
        basic_auth {username} {password}
        hide_ip
        hide_via
        probe_resistance {probe_domain}
    }}

    reverse_proxy {upstream} {{
        header_up Host {{host}}
        header_up X-Real-IP {{remote_host}}
    }}

    file_server {{
        root /var/www/html
    }}
}}
"#,
        port = site.port,
        email = quoted(site.email.as_str()),
        username = quoted(site.credentials.username.as_str()),
        password = quoted(site.credentials.password.as_str()),
        probe_domain = quoted(site.probe_domain.as_str()),
        upstream = quoted(&site.upstream.render()),
    )
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::naive::caddy::site::CaddySite;

    fn caddyfile() -> String {
        render(
            &CaddySite::parse(
                8443,
                "admin@example.com",
                "a3f9c2b1",
                "xK-_9Zq",
                "www.bing.com",
                "http://127.0.0.1:8000",
            )
            .unwrap(),
        )
    }

    #[test]
    fn every_value_reaches_the_file_as_one_quoted_token() {
        let config = caddyfile();
        assert!(config.contains("\n:8443 {\n"));
        assert!(config.contains("    tls \"admin@example.com\" {\n"));
        assert!(config.contains("        basic_auth \"a3f9c2b1\" \"xK-_9Zq\"\n"));
        assert!(config.contains("        probe_resistance \"www.bing.com\"\n"));
        assert!(config.contains("    reverse_proxy \"http://127.0.0.1:8000\" {\n"));
    }

    #[test]
    fn the_placeholders_caddy_expands_itself_are_left_alone() {
        let config = caddyfile();
        assert!(config.contains("        header_up Host {host}\n"));
        assert!(config.contains("        header_up X-Real-IP {remote_host}\n"));
    }

    #[test]
    fn the_braces_of_the_file_balance() {
        let config = caddyfile();
        let opened = config.matches('{').count();
        let closed = config.matches('}').count();
        assert_eq!(opened, closed);
    }

    #[test]
    fn the_file_ends_with_a_newline() {
        assert!(caddyfile().ends_with("}\n"));
    }
}
