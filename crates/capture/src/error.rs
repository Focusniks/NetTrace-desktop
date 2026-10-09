use std::io;

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("unknown capture file format")]
    UnknownFormat,
    #[error("unsupported capture format version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("corrupt capture at offset {offset}: {reason}")]
    Corrupt { offset: u64, reason: &'static str },
    #[error("capture is truncated at offset {offset}")]
    Truncated { offset: u64 },
}

impl CaptureError {
    /// Stable code for the UI layer.
    pub fn code(&self) -> &'static str {
        match self {
            CaptureError::Io(_) => "io",
            CaptureError::UnknownFormat => "unknown_format",
            CaptureError::UnsupportedVersion { .. } => "unsupported_version",
            CaptureError::Corrupt { .. } => "corrupt",
            CaptureError::Truncated { .. } => "truncated",
        }
    }
}

/// Maps an unexpected EOF while reading a structure into `Truncated`.
pub(crate) fn eof_as_truncated(err: io::Error, offset: u64) -> CaptureError {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        CaptureError::Truncated { offset }
    } else {
        CaptureError::Io(err)
    }
}
