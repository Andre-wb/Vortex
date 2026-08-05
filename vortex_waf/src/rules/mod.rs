//! Правила детектирования и их поставщики.

pub mod catalog;
pub mod catalog_source;
pub mod category;
pub mod composite_source;
pub mod pattern_rule;
pub mod patterns;
pub mod regex_matcher;
pub mod static_source;
pub mod substring_matcher;

pub use catalog_source::CatalogRuleSource;
pub use category::RuleCategory;
pub use composite_source::CompositeRuleSource;
pub use pattern_rule::PatternRule;
pub use regex_matcher::RegexMatcher;
pub use static_source::StaticRuleSource;
pub use substring_matcher::SubstringMatcher;
