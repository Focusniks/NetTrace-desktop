use crate::error::{ErrorCode, QueryError};

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    /// Field name or bare literal (numbers, addresses, CIDR, MAC …).
    Word(String),
    /// Quoted string (escapes already processed).
    Str(String),
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    And,
    Or,
    Not,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    In,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub tok: Tok,
    pub start: usize,
    pub end: usize,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-' | '/')
}

pub fn lex(input: &str) -> Result<Vec<Token>, QueryError> {
    let bytes: Vec<(usize, char)> = input.char_indices().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let at = |i: usize| bytes.get(i).map(|(_, c)| *c);
    let pos = |i: usize| bytes.get(i).map(|(p, _)| *p).unwrap_or(input.len());
    while i < bytes.len() {
        let c = bytes[i].1;
        let start = pos(i);
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let two = |a: char, b: char| c == a && at(i + 1) == Some(b);
        let (tok, len) = if two('=', '=') {
            (Tok::Eq, 2)
        } else if two('!', '=') {
            (Tok::Ne, 2)
        } else if two('<', '=') {
            (Tok::Le, 2)
        } else if two('>', '=') {
            (Tok::Ge, 2)
        } else if two('&', '&') {
            (Tok::And, 2)
        } else if two('|', '|') {
            (Tok::Or, 2)
        } else {
            match c {
                '(' => (Tok::LParen, 1),
                ')' => (Tok::RParen, 1),
                '{' => (Tok::LBrace, 1),
                '}' => (Tok::RBrace, 1),
                ',' => (Tok::Comma, 1),
                '!' => (Tok::Not, 1),
                '<' => (Tok::Lt, 1),
                '>' => (Tok::Gt, 1),
                '=' => {
                    return Err(QueryError::new(ErrorCode::SingleEquals, start, start + 1, "="));
                }
                '"' => {
                    let mut s = String::new();
                    let mut j = i + 1;
                    loop {
                        match at(j) {
                            None => {
                                return Err(QueryError::new(ErrorCode::UnterminatedString, start, input.len(), ""));
                            }
                            Some('"') => break,
                            Some('\\') => {
                                let esc_at = pos(j);
                                match at(j + 1) {
                                    Some('"') => s.push('"'),
                                    Some('\\') => s.push('\\'),
                                    Some('n') => s.push('\n'),
                                    Some('r') => s.push('\r'),
                                    Some('t') => s.push('\t'),
                                    Some('x') => {
                                        let hex: String = [at(j + 2), at(j + 3)].iter().flatten().collect();
                                        let v = u8::from_str_radix(&hex, 16).ok().filter(|_| hex.len() == 2).ok_or_else(|| {
                                            QueryError::new(ErrorCode::BadEscape, esc_at, pos(j + 4).min(input.len()), &hex)
                                        })?;
                                        s.push(char::from(v));
                                        j += 2;
                                    }
                                    _ => {
                                        return Err(QueryError::new(ErrorCode::BadEscape, esc_at, pos(j + 2), ""));
                                    }
                                }
                                j += 2;
                            }
                            Some(ch) => {
                                s.push(ch);
                                j += 1;
                            }
                        }
                    }
                    out.push(Token { tok: Tok::Str(s), start, end: pos(j + 1) });
                    i = j + 1;
                    continue;
                }
                c if is_word_char(c) => {
                    let mut j = i;
                    while at(j).is_some_and(is_word_char) {
                        j += 1;
                    }
                    let word: String = bytes[i..j].iter().map(|(_, c)| *c).collect();
                    let tok = match word.to_ascii_lowercase().as_str() {
                        "and" => Tok::And,
                        "or" => Tok::Or,
                        "not" => Tok::Not,
                        "eq" => Tok::Eq,
                        "ne" => Tok::Ne,
                        "lt" => Tok::Lt,
                        "le" => Tok::Le,
                        "gt" => Tok::Gt,
                        "ge" => Tok::Ge,
                        "contains" => Tok::Contains,
                        "in" => Tok::In,
                        _ => Tok::Word(word),
                    };
                    out.push(Token { tok, start, end: pos(j) });
                    i = j;
                    continue;
                }
                other => {
                    return Err(QueryError::new(ErrorCode::UnexpectedChar, start, start + other.len_utf8(), &other.to_string()));
                }
            }
        };
        out.push(Token { tok, start, end: pos(i + len) });
        i += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        lex(s).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn operators_and_words() {
        assert_eq!(
            toks("ip.addr==10.0.0.1&&!tcp"),
            vec![Tok::Word("ip.addr".into()), Tok::Eq, Tok::Word("10.0.0.1".into()), Tok::And, Tok::Not, Tok::Word("tcp".into())]
        );
        assert_eq!(toks("a and b OR not c"), vec![
            Tok::Word("a".into()), Tok::And, Tok::Word("b".into()), Tok::Or, Tok::Not, Tok::Word("c".into())
        ]);
        assert_eq!(toks("x != fe80::1"), vec![Tok::Word("x".into()), Tok::Ne, Tok::Word("fe80::1".into())]);
        assert_eq!(toks("p in {80, 443}"), vec![
            Tok::Word("p".into()), Tok::In, Tok::LBrace, Tok::Word("80".into()), Tok::Comma, Tok::Word("443".into()), Tok::RBrace
        ]);
    }

    #[test]
    fn strings_and_escapes() {
        assert_eq!(toks(r#"h contains "a\"b\x41""#), vec![Tok::Word("h".into()), Tok::Contains, Tok::Str("a\"bA".into())]);
        let e = lex(r#"h == "abc"#).unwrap_err();
        assert_eq!(e.code, ErrorCode::UnterminatedString);
        assert_eq!(lex(r#""\q""#).unwrap_err().code, ErrorCode::BadEscape);
        assert_eq!(lex(r#""\x4""#).unwrap_err().code, ErrorCode::BadEscape);
    }

    #[test]
    fn errors_have_spans() {
        let e = lex("ip.src = 1").unwrap_err();
        assert_eq!((e.code, e.start, e.end), (ErrorCode::SingleEquals, 7, 8));
        let e = lex("a # b").unwrap_err();
        assert_eq!((e.code, e.start), (ErrorCode::UnexpectedChar, 2));
        // Non-ASCII input is handled without byte-index panics.
        assert_eq!(lex("ip.src == «»").unwrap_err().code, ErrorCode::UnexpectedChar);
        assert_eq!(toks("h == \"привет\""), vec![Tok::Word("h".into()), Tok::Eq, Tok::Str("привет".into())]);
    }
}
