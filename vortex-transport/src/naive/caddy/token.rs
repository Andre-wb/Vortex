pub fn quoted(value: &str) -> String {
    let mut token = String::with_capacity(value.len() + 2);
    token.push('"');
    for symbol in value.chars() {
        if symbol == '"' || symbol == '\\' {
            token.push('\\');
        }
        token.push(symbol);
    }
    token.push('"');
    token
}

#[cfg(test)]
mod tests {
    use super::quoted;

    #[test]
    fn a_plain_value_is_wrapped_in_quotes() {
        assert_eq!(quoted("a3f9c2b1"), "\"a3f9c2b1\"");
    }

    #[test]
    fn a_quote_and_a_backslash_are_escaped() {
        assert_eq!(quoted("a\"b"), "\"a\\\"b\"");
        assert_eq!(quoted("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn an_empty_value_still_becomes_one_token() {
        assert_eq!(quoted(""), "\"\"");
    }
}
