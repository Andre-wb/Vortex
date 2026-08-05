//! Реализации разборщиков тела. Новый формат — новый файл.

pub mod form_urlencoded;
pub mod json;
pub mod multipart;

pub use form_urlencoded::FormUrlEncodedParser;
pub use json::JsonBodyParser;
pub use multipart::MultipartParser;
