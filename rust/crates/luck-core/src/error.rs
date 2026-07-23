use thiserror::Error;

pub type Result<T> = std::result::Result<T, LuckError>;

#[derive(Debug, Error)]
pub enum LuckError {
    #[error("input is empty")]
    EmptyInput,
    #[error("input size {actual} exceeds limit {limit}")]
    InputTooLarge { actual: usize, limit: usize },
    #[error("cookie count {actual} exceeds limit {limit}")]
    TooManyCookies { actual: usize, limit: usize },
    #[error("unsupported cookie format")]
    UnsupportedFormat,
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("query parse failed at byte {offset}: {message}")]
    Query { offset: usize, message: String },
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
