use std::fmt;

#[derive(Debug)]
pub enum CertGenError {
    UnsupportedAlgorithm(i32),
    UnsupportedEcCurve(i32),
    KeyGenFailed(String),
    SerializationFailed(String),
    InvalidParameter(String),
}

impl fmt::Display for CertGenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(v) => write!(f, "unsupported algorithm: {v}"),
            Self::UnsupportedEcCurve(v) => write!(f, "unsupported EC curve: {v}"),
            Self::KeyGenFailed(msg) => write!(f, "key generation failed: {msg}"),
            Self::SerializationFailed(msg) => write!(f, "serialization failed: {msg}"),
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {msg}"),
        }
    }
}

impl std::error::Error for CertGenError {}

pub type Result<T> = std::result::Result<T, CertGenError>;
