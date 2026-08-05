//! Паттерны внешних XML-сущностей.

pub const PATTERNS: &[(&str, &str)] = &[
    (r"(<!DOCTYPE.*\[.*\])", "XML DOCTYPE Declaration"),
    (r"(<!ENTITY.*SYSTEM.*>)", "XML External Entity"),
    (
        r"(file:///|http://|ftp://).*ENTITY",
        "External Entity Reference",
    ),
    (r"\b(XXE|XML External Entity)\b", "XXE Keyword"),
    (r"(<!ELEMENT|<!ATTLIST)", "XML Schema Elements"),
];
