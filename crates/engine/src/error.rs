use nettrace_model::FilterError;
use nettrace_query::QueryError;
use serde::Serialize;

/// Errors returned to the UI. Serialized as `{ code, message, filter? }`.
#[derive(Debug, thiserror::Error, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineError {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<FilterError>,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl EngineError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        EngineError { code, message: message.into(), filter: None }
    }

    pub fn no_capture() -> Self {
        Self::new("no_capture", "no capture is open")
    }

    pub fn not_found(what: &str) -> Self {
        Self::new("not_found", format!("{what} not found"))
    }

    pub fn cancelled() -> Self {
        Self::new("cancelled", "superseded by a newer request")
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        EngineError::new("io", e.to_string())
    }
}

impl From<nettrace_capture::CaptureError> for EngineError {
    fn from(e: nettrace_capture::CaptureError) -> Self {
        EngineError::new(e.code(), e.to_string())
    }
}

pub fn filter_error(e: &QueryError) -> FilterError {
    FilterError {
        code: e.code.as_str().to_owned(),
        start: e.start as u32,
        end: e.end as u32,
        detail: e.detail.clone(),
    }
}

impl From<QueryError> for EngineError {
    fn from(e: QueryError) -> Self {
        EngineError { code: "filter", message: e.to_string(), filter: Some(filter_error(&e)) }
    }
}

pub type Result<T> = std::result::Result<T, EngineError>;
