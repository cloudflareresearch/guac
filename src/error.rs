use thiserror::Error;

/// Failures at configuration, message, cryptographic, or storage boundaries.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Configuration(&'static str),
    #[error("malformed message")]
    Malformed,
    #[error("unsupported protocol type {0:#06x}")]
    Unsupported(u16),
    #[error("configuration or challenge mismatch")]
    Mismatch,
    #[error("unknown or expired challenge")]
    Challenge,
    #[error("already consumed or recovery expired")]
    Replay,
    #[error("key or credential context retired")]
    Retired,
    #[error("invalid credit amount")]
    Amount,
    #[error("unknown or expired grant session")]
    Session,
    #[error("storage failure: {0}")]
    Storage(String),
    #[error("entropy unavailable")]
    Entropy,
    #[error("endorsement cryptography failed: {0}")]
    Endorsement(String),
    #[error("credential cryptography failed: {0}")]
    Credential(String),
}

// Upstream variants that need distinct caller action keep their own variant;
// the rest are cryptographic failures carried as text.
impl From<ec_ihat::Error> for Error {
    fn from(error: ec_ihat::Error) -> Self {
        match error {
            ec_ihat::Error::Deserialize => Self::Malformed,
            ec_ihat::Error::Entropy => Self::Entropy,
            error => Self::Endorsement(error.to_string()),
        }
    }
}

impl From<act::Error> for Error {
    fn from(error: act::Error) -> Self {
        match error {
            act::Error::Deserialize => Self::Malformed,
            act::Error::Amount => Self::Amount,
            act::Error::Entropy => Self::Entropy,
            error => Self::Credential(error.to_string()),
        }
    }
}
