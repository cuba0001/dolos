use std::error::Error;
use std::fmt;

pub type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Debug)]
pub struct ProxyError {
    stage: &'static str,
    source: BoxError,
}

impl ProxyError {
    pub fn new(stage: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            stage,
            source: Box::new(source),
        }
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.source)
    }
}

impl Error for ProxyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub trait ResultExt<T> {
    fn context(self, stage: &'static str) -> Result<T, ProxyError>;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: Error + Send + Sync + 'static,
{
    fn context(self, stage: &'static str) -> Result<T, ProxyError> {
        self.map_err(|error| ProxyError::new(stage, error))
    }
}

pub fn invalid(stage: &'static str, message: &'static str) -> ProxyError {
    ProxyError::new(
        stage,
        std::io::Error::new(std::io::ErrorKind::InvalidData, message),
    )
}
