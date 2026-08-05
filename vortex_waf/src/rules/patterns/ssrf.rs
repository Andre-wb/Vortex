//! Паттерны подделки запросов на стороне сервера.

pub const PATTERNS: &[(&str, &str)] = &[
    (
        r"(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)",
        "Localhost Access",
    ),
    (
        r"(169\.254\.169\.254|metadata\.google\.internal)",
        "Cloud Metadata",
    ),
    (
        r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+)",
        "Private IP Range",
    ),
    (
        r"(file://|ftp://|gopher://|dict://)",
        "Dangerous URL Schemes",
    ),
    (
        r"(admin|internal|backend|management)",
        "Internal Service Names",
    ),
];
