use thiserror::Error;
use std::fmt::Debug;
use scs_client::error::ScsError;

#[derive(Error, Debug)]
pub enum TunError {
    #[error("scs: {0}")]
    Scs(ScsError),

    #[error("other: {0}")]
    Other(String),
}

impl From<&str> for TunError {
    fn from(other: &str) -> Self {
        Self::Other(other.to_string())
    }
}

impl From<ScsError> for TunError {
    fn from(other: ScsError) -> Self {
        Self::Scs(other)
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
