//! Паттерны злоупотребления API.

pub const PATTERNS: &[(&str, &str)] = &[
    (r"(/api/.*(admin|delete|drop|truncate))", "Admin API Abuse"),
    (r"(/v[0-9]+/.*)", "API Version Enumeration"),
    (r"(swagger|openapi|api-docs)", "API Documentation"),
    (r"(\.json|\.xml|\.yaml|\.yml)", "API Data Formats"),
    (r"(limit=1000|limit=9999)", "Large Result Set"),
    (r"(offset=10000|page=1000)", "Deep Pagination"),
];
