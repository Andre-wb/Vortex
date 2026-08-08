pub mod verdict;

use verdict::TransportVerdict;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub received_at: f64,
    pub verdicts: Vec<TransportVerdict>,
}

impl Report {
    pub fn of(pairs: &[(String, bool)], received_at: f64) -> Option<Report> {
        let mut verdicts: Vec<TransportVerdict> = Vec::new();
        for (transport, ok) in pairs {
            let Some(verdict) = TransportVerdict::parse(transport, *ok) else {
                continue;
            };
            match verdicts
                .iter_mut()
                .find(|known| known.transport == verdict.transport)
            {
                Some(known) => known.ok = verdict.ok,
                None => verdicts.push(verdict),
            }
        }
        if verdicts.is_empty() {
            return None;
        }
        Some(Report {
            received_at,
            verdicts,
        })
    }

    pub fn says(&self, transport: &str) -> Option<bool> {
        self.verdicts
            .iter()
            .find(|verdict| verdict.transport == transport)
            .map(|verdict| verdict.ok)
    }

    pub fn encode(&self) -> String {
        let body: Vec<String> = self
            .verdicts
            .iter()
            .map(|verdict| format!("{}={}", verdict.transport, u8::from(verdict.ok)))
            .collect();
        format!("{}|{}", self.received_at, body.join(","))
    }

    pub fn decode(value: &str) -> Option<Report> {
        let (stamp, body) = value.split_once('|')?;
        let received_at: f64 = stamp.parse().ok()?;
        if !received_at.is_finite() {
            return None;
        }
        let pairs: Vec<(String, bool)> = body
            .split(',')
            .filter_map(|item| {
                let (transport, flag) = item.split_once('=')?;
                Some((transport.to_owned(), flag == "1"))
            })
            .collect();
        Report::of(&pairs, received_at)
    }
}

#[cfg(test)]
mod tests {
    use super::Report;

    fn pairs(items: &[(&str, bool)]) -> Vec<(String, bool)> {
        items
            .iter()
            .map(|(name, ok)| ((*name).to_owned(), *ok))
            .collect()
    }

    #[test]
    fn a_report_keeps_only_the_transports_the_catalogue_knows() {
        let report = Report::of(&pairs(&[("tor", true), ("vmess", false)]), 10.0).unwrap();
        assert_eq!(report.verdicts.len(), 1);
        assert_eq!(report.says("tor"), Some(true));
        assert_eq!(report.says("vmess"), None);
    }

    #[test]
    fn a_report_about_nothing_known_is_not_a_report() {
        assert_eq!(Report::of(&pairs(&[("vmess", false)]), 10.0), None);
        assert_eq!(Report::of(&[], 10.0), None);
    }

    #[test]
    fn a_transport_named_twice_is_counted_once() {
        let report = Report::of(&pairs(&[("tor", true), ("tor", false)]), 10.0).unwrap();
        assert_eq!(report.verdicts.len(), 1);
        assert_eq!(report.says("tor"), Some(false));
    }

    #[test]
    fn a_report_survives_the_trip_through_the_store() {
        let report = Report::of(&pairs(&[("tor", true), ("sse", false)]), 1234.5).unwrap();
        assert_eq!(Report::decode(&report.encode()), Some(report));
    }

    #[test]
    fn nothing_the_store_did_not_write_decodes_into_a_report() {
        assert_eq!(Report::decode(""), None);
        assert_eq!(Report::decode("10.0"), None);
        assert_eq!(Report::decode("nan|tor=1"), None);
        assert_eq!(Report::decode("inf|tor=1"), None);
        assert_eq!(Report::decode("10.0|"), None);
        assert_eq!(Report::decode("10.0|vmess=1"), None);
    }

    #[test]
    fn a_verdict_the_store_cannot_read_does_not_take_the_whole_report_with_it() {
        let report = Report::decode("10.0|vmess=1,tor=0").unwrap();
        assert_eq!(report.says("tor"), Some(false));
        assert_eq!(report.verdicts.len(), 1);
    }
}
