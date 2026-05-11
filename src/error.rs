use thiserror::Error;

#[derive(Error, Debug)]
pub enum IpmiError {
    #[error("socket error: {0}")]
    Socket(String),
    #[error("timeout")]
    Timeout,
    #[error("bad response")]
    BadResponse,
    #[error("cipher suite mismatch")]
    CipherMismatch,
    #[error("auth failed")]
    AuthFailed,
    #[error("decrypt failed")]
    DecryptFailed,
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
}

pub type Result<T> = std::result::Result<T, IpmiError>;
