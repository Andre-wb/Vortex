pub const CHROME_ORDER: [&str; 22] = [
    ":method",
    ":authority",
    ":scheme",
    ":path",
    "host",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
    "accept-language",
    "cookie",
    "content-type",
    "content-length",
    "origin",
];

pub fn rank_of(name: &str) -> Option<usize> {
    let lowered = name.to_ascii_lowercase();
    CHROME_ORDER.iter().position(|known| *known == lowered)
}

pub fn arrange(fields: &[(String, String)]) -> Vec<(String, String)> {
    let mut collapsed: Vec<(String, String)> = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        let lowered = name.to_ascii_lowercase();
        match collapsed
            .iter_mut()
            .find(|(held, _)| held.to_ascii_lowercase() == lowered)
        {
            Some(held) => *held = (name.clone(), value.clone()),
            None => collapsed.push((name.clone(), value.clone())),
        }
    }

    let mut known: Vec<(usize, (String, String))> = Vec::new();
    let mut rest: Vec<(String, String)> = Vec::new();
    for field in collapsed {
        match rank_of(&field.0) {
            Some(rank) => known.push((rank, field)),
            None => rest.push(field),
        }
    }
    known.sort_by_key(|(rank, _)| *rank);

    let mut out: Vec<(String, String)> = known.into_iter().map(|(_, field)| field).collect();
    out.extend(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::{arrange, rank_of, CHROME_ORDER};

    fn fields(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn names(fields: &[(String, String)]) -> Vec<String> {
        fields.iter().map(|(name, _)| name.clone()).collect()
    }

    #[test]
    fn the_headers_a_browser_sends_come_out_in_the_order_a_browser_sends_them() {
        let sent = fields(&[
            ("Accept-Language", "ru"),
            ("User-Agent", "Chrome"),
            ("Host", "example.org"),
            ("Accept", "*/*"),
        ]);
        assert_eq!(
            names(&arrange(&sent)),
            vec!["Host", "User-Agent", "Accept", "Accept-Language"]
        );
    }

    #[test]
    fn the_case_the_client_wrote_a_name_in_is_the_case_it_comes_back_in() {
        let sent = fields(&[("uSeR-aGeNt", "Chrome")]);
        assert_eq!(names(&arrange(&sent)), vec!["uSeR-aGeNt"]);
    }

    #[test]
    fn a_header_a_browser_never_sends_goes_after_the_ones_it_does() {
        let sent = fields(&[
            ("X-Request-Id", "1"),
            ("Accept", "*/*"),
            ("X-Trace", "2"),
            ("Host", "example.org"),
        ]);
        assert_eq!(
            names(&arrange(&sent)),
            vec!["Host", "Accept", "X-Request-Id", "X-Trace"]
        );
    }

    #[test]
    fn a_header_sent_twice_comes_back_once_with_the_value_that_came_last() {
        let sent = fields(&[("Accept", "text/html"), ("accept", "*/*")]);
        let arranged = arrange(&sent);
        assert_eq!(arranged.len(), 1);
        assert_eq!(arranged[0].1, "*/*");
    }

    #[test]
    fn nothing_arranged_is_nothing() {
        assert!(arrange(&[]).is_empty());
    }

    #[test]
    fn every_name_the_order_knows_has_a_place_in_it() {
        for (index, name) in CHROME_ORDER.iter().enumerate() {
            assert_eq!(rank_of(name), Some(index));
            assert_eq!(rank_of(&name.to_uppercase()), Some(index));
        }
        assert_eq!(rank_of("x-request-id"), None);
    }
}
