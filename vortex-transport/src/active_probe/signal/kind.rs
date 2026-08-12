use crate::net::cidr::Cidr;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Signal {
    CensorNetwork(Cidr),
    MissingBrowserHeaders(usize),
    NoUserAgent,
    ShortUserAgent,
    BotUserAgent(String),
    Replay(f64),
    NoCookies,
    AcceptMismatch,
}

impl Signal {
    pub fn name(&self) -> &'static str {
        match self {
            Signal::CensorNetwork(_) => "censor_net",
            Signal::MissingBrowserHeaders(_) => "missing_headers",
            Signal::NoUserAgent => "no_user_agent",
            Signal::ShortUserAgent => "short_ua",
            Signal::BotUserAgent(_) => "bot_ua",
            Signal::Replay(_) => "replay",
            Signal::NoCookies => "no_cookies",
            Signal::AcceptMismatch => "accept_mismatch",
        }
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signal::CensorNetwork(network) => write!(f, "censor_net:{network}"),
            Signal::MissingBrowserHeaders(count) => write!(f, "missing_headers:{count}"),
            Signal::BotUserAgent(agent) => write!(f, "bot_ua:{agent}"),
            Signal::Replay(elapsed) => write!(f, "replay:{elapsed:.1}s"),
            other => write!(f, "{}", other.name()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Signal;
    use crate::net::cidr::Cidr;

    #[test]
    fn a_signal_says_what_it_saw_and_where() {
        let network = Cidr::parse("109.124.0.0/16").unwrap();
        assert_eq!(
            Signal::CensorNetwork(network).to_string(),
            "censor_net:109.124.0.0/16"
        );
        assert_eq!(
            Signal::MissingBrowserHeaders(5).to_string(),
            "missing_headers:5"
        );
        assert_eq!(Signal::Replay(1.25).to_string(), "replay:1.2s");
    }

    #[test]
    fn a_signal_that_carries_nothing_is_written_as_its_name_alone() {
        assert_eq!(Signal::NoCookies.to_string(), "no_cookies");
        assert_eq!(Signal::NoUserAgent.to_string(), "no_user_agent");
        assert_eq!(Signal::ShortUserAgent.to_string(), "short_ua");
        assert_eq!(Signal::AcceptMismatch.to_string(), "accept_mismatch");
    }

    #[test]
    fn the_name_of_a_signal_never_carries_the_value_that_raised_it() {
        let network = Cidr::parse("109.124.0.0/16").unwrap();
        assert_eq!(Signal::CensorNetwork(network).name(), "censor_net");
        assert_eq!(Signal::BotUserAgent("sqlmap".to_owned()).name(), "bot_ua");
    }
}
