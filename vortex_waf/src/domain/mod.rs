//! Слой домена: типы, ничего не знающие ни о хранилищах, ни о транспорте.

pub mod action;
pub mod analysis;
pub mod block_record;
pub mod body_field;
pub mod client_ip;
pub mod content_type;
pub mod decision;
pub mod finding;
pub mod header_map;
pub mod http_method;
pub mod param_map;
pub mod request;
pub mod request_builder;
pub mod rule_id;
pub mod rule_meta;
pub mod severity;
pub mod timestamp;

pub use action::Action;
pub use analysis::Analysis;
pub use block_record::BlockRecord;
pub use body_field::BodyField;
pub use client_ip::ClientIp;
pub use content_type::ContentType;
pub use decision::Decision;
pub use finding::Finding;
pub use header_map::HeaderMap;
pub use http_method::HttpMethod;
pub use param_map::ParamMap;
pub use request::InspectedRequest;
pub use request_builder::RequestBuilder;
pub use rule_id::RuleId;
pub use rule_meta::RuleMeta;
pub use severity::Severity;
pub use timestamp::Timestamp;
