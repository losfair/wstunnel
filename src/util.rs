use std::fmt::Debug;

pub trait E2s<T, E> {
    fn e2s(self, desc: &str) -> Result<T, String>;
}

impl<T, E: Debug> E2s<T, E> for Result<T, E> {
    fn e2s(self, desc: &str) -> Result<T, String> {
        match self {
            Ok(x) => Ok(x),
            Err(e) => Err(format!("{}: {:?}", desc, e)),
        }
    }
}
