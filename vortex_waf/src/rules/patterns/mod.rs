//! Таблицы сигнатур. Каждый файл — одна категория атак и ничего больше.

pub mod api_abuse;
pub mod command_injection;
pub mod file_inclusion;
pub mod path_traversal;
pub mod scanner;
pub mod sql_injection;
pub mod ssrf;
pub mod xss;
pub mod xxe;
