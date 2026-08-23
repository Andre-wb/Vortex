use crate::time::stamp::Stamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedSubscription {
    pub user_id: i64,
    pub endpoint: String,
    pub app_id: String,
    pub created_at: Stamp,
    pub failures: i64,
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::UnifiedSubscription;
    use crate::time::stamp::Stamp;

    fn subscription(endpoint: &str) -> UnifiedSubscription {
        UnifiedSubscription {
            user_id: 7,
            endpoint: endpoint.to_owned(),
            app_id: "org.vortex.messenger".to_owned(),
            created_at: Stamp::from_unix(1_785_834_930, 0).unwrap(),
            failures: 0,
            active: true,
        }
    }

    #[test]
    fn a_subscription_names_the_distributor_endpoint() {
        assert_eq!(
            subscription("https://ntfy.test/abc").endpoint,
            "https://ntfy.test/abc"
        );
    }

    #[test]
    fn two_endpoints_of_one_account_are_two_subscriptions() {
        assert_ne!(
            subscription("https://a.test/x"),
            subscription("https://b.test/y")
        );
    }
}
