use thiserror::Error;
use std::fmt::Debug;

#[derive(Error, Debug, Clone)]
pub enum TunError {
    #[error("other: {0}")]
    Other(String),
}

impl From<&str> for TunError {
    fn from(other: &str) -> Self {
        Self::Other(other.to_string())
    }
}

pub trait E2s<T, E> {
    fn e2s(self, desc: &str) -> Result<T, TunError>;
}

impl<T, E: Debug> E2s<T, E> for Result<T, E> {
    fn e2s(self, desc: &str) -> Result<T, TunError> {
        match self {
            Ok(x) => Ok(x),
            Err(e) => Err(TunError::Other(format!("{}: {:?}", desc, e))),
        }
    }
}
