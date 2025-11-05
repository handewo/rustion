use std::num::ParseIntError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("empty file")]
    EmptyFile,
    #[error("not a v3 asciicast file")]
    InvalidVersion,
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("invalid cols value in resize event: {0}")]
    InvalidCols(ParseIntError),
    #[error("invalid rows value in resize event: {0}")]
    InvalidRows(ParseIntError),
    #[error("invalid size value in resize event")]
    InvalidResize,
    #[error("invalid exit value: {0}")]
    InvalidExit(ParseIntError),
}
