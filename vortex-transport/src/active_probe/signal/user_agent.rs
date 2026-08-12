use crate::active_probe::signal::kind::Signal;

pub const TOOL_NAMES: [&str; 10] = [
    "curl", "wget", "python", "go-http", "java/", "scanner", "nikto", "sqlmap", "nmap", "masscan",
];

pub const NAMED_LENGTH: usize = 30;

pub fn read(agent: &str, short_below: usize) -> Option<Signal> {
    if agent.is_empty() {
        return Some(Signal::NoUserAgent);
    }
    if agent.chars().count() < short_below {
        return Some(Signal::ShortUserAgent);
    }
    if let Some(tool) = tool_in(agent) {
        return Some(Signal::BotUserAgent(tool));
    }
    None
}

fn tool_in(agent: &str) -> Option<String> {
    let lowered = agent.to_lowercase();
    if TOOL_NAMES.iter().any(|name| lowered.contains(name)) {
        return Some(agent.chars().take(NAMED_LENGTH).collect());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::read;
    use crate::active_probe::signal::kind::Signal;

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    #[test]
    fn a_browser_agent_raises_nothing() {
        assert_eq!(read(CHROME, 20), None);
    }

    #[test]
    fn a_client_that_names_no_agent_at_all_is_a_signal() {
        assert_eq!(read("", 20), Some(Signal::NoUserAgent));
    }

    #[test]
    fn an_agent_too_short_to_be_a_browser_is_a_signal() {
        assert_eq!(read("curl/8.4.0", 20), Some(Signal::ShortUserAgent));
        assert_eq!(
            read("python-httpx/0.28.1", 20),
            Some(Signal::ShortUserAgent)
        );
    }

    #[test]
    fn a_scanner_that_writes_a_long_enough_name_is_still_recognised() {
        assert_eq!(
            read("sqlmap/1.7.11#stable (https://sqlmap.org)", 20),
            Some(Signal::BotUserAgent(
                "sqlmap/1.7.11#stable (https://s".chars().take(30).collect()
            ))
        );
        assert!(matches!(
            read("Mozilla/5.0 masscan/1.3.2 probe", 20),
            Some(Signal::BotUserAgent(_))
        ));
    }

    #[test]
    fn the_name_of_a_tool_is_recognised_whatever_case_it_is_written_in() {
        assert!(matches!(
            read("SQLMAP/1.7.11#stable (https://x)", 20),
            Some(Signal::BotUserAgent(_))
        ));
    }

    #[test]
    fn the_agent_that_reaches_the_log_is_never_longer_than_the_room_it_gets() {
        let long = format!("curl {}", "a".repeat(500));
        match read(&long, 20) {
            Some(Signal::BotUserAgent(named)) => assert_eq!(named.chars().count(), 30),
            other => panic!("ожидался bot_ua, получено {other:?}"),
        }
    }

    #[test]
    fn an_agent_is_measured_in_characters_and_not_in_bytes() {
        let cyrillic = "Ярославль-браузер";
        assert_eq!(cyrillic.chars().count(), 17);
        assert_eq!(read(cyrillic, 20), Some(Signal::ShortUserAgent));
    }
}
