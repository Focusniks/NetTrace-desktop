use std::fmt;

/// Stable error codes; the UI maps them to localized messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Empty,
    UnexpectedChar,
    UnterminatedString,
    BadEscape,
    SingleEquals,
    UnexpectedToken,
    UnexpectedEnd,
    ExpectedValue,
    UnclosedParen,
    UnknownField,
    InvalidValue,
    OperatorNotSupported,
    TooComplex,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Empty => "empty",
            ErrorCode::UnexpectedChar => "unexpected_char",
            ErrorCode::UnterminatedString => "unterminated_string",
            ErrorCode::BadEscape => "bad_escape",
            ErrorCode::SingleEquals => "single_equals",
            ErrorCode::UnexpectedToken => "unexpected_token",
            ErrorCode::UnexpectedEnd => "unexpected_end",
            ErrorCode::ExpectedValue => "expected_value",
            ErrorCode::UnclosedParen => "unclosed_paren",
            ErrorCode::UnknownField => "unknown_field",
            ErrorCode::InvalidValue => "invalid_value",
            ErrorCode::OperatorNotSupported => "operator_not_supported",
            ErrorCode::TooComplex => "too_complex",
        }
    }
}

/// Error with a byte span into the filter text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError {
    pub code: ErrorCode,
    pub start: usize,
    pub end: usize,
    /// Offending token or expected type, for the message.
    pub detail: String,
}

impl QueryError {
    pub fn new(code: ErrorCode, start: usize, end: usize, detail: &str) -> Self {
        QueryError { code, start, end, detail: detail.to_owned() }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}..{}: {}", self.code.as_str(), self.start, self.end, self.detail)
    }
}

impl std::error::Error for QueryError {}
