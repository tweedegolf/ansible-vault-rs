use aes_ctr::cipher::stream::InvalidKeyNonceLength;
use block_padding::{PadError, UnpadError};
use hmac::crypto_mac::MacError;
use std::error::Error;
use std::fmt;

/// A specialized `Result` type for decrypting Ansible vaults results
pub type Result<T> = std::result::Result<T, VaultError>;

/// The error type for decrypting Ansible vaults.
#[derive(Debug)]
pub struct VaultError {
    pub kind: ErrorKind,
    pub message: String,
}

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    Error,
    IoError,
    NotAVault,
    InvalidFormat,
    IncorrectSecret,
}

fn kind_message(kind: &ErrorKind) -> &str {
    match kind {
        ErrorKind::Error => "Error !",
        ErrorKind::IoError => "Io error",
        ErrorKind::NotAVault => "Input is not a vault",
        ErrorKind::InvalidFormat => "Invalid data format : vault is incorrect",
        ErrorKind::IncorrectSecret => "Invalid secret",
    }
}

impl VaultError {
    pub fn new(kind: ErrorKind, message: &str) -> Self {
        VaultError {
            kind,
            message: message.to_string(),
        }
    }

    pub fn from_kind(kind: ErrorKind) -> Self {
        let msg = kind_message(&kind).to_string();

        VaultError { kind, message: msg }
    }

    pub fn from_string(message: &str) -> Self {
        VaultError {
            kind: ErrorKind::Error,
            message: message.to_string(),
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for VaultError {
    fn description(&self) -> &str {
        &self.message
    }
}

impl From<&str> for VaultError {
    fn from(s: &str) -> Self {
        VaultError::from_string(s)
    }
}

impl std::cmp::PartialEq for VaultError {
    fn eq(&self, other: &VaultError) -> bool {
        self.kind.eq(&other.kind)
    }
}

impl From<std::io::Error> for VaultError {
    fn from(error: std::io::Error) -> Self {
        VaultError::new(ErrorKind::IoError, &error.to_string())
    }
}

impl From<std::string::FromUtf8Error> for VaultError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        VaultError::new(ErrorKind::InvalidFormat, &error.to_string())
    }
}

impl From<hex::FromHexError> for VaultError {
    fn from(error: hex::FromHexError) -> Self {
        VaultError::new(ErrorKind::InvalidFormat, &error.to_string())
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for VaultError {
    fn from(error: hmac::crypto_mac::InvalidKeyLength) -> Self {
        VaultError::new(ErrorKind::InvalidFormat, &error.to_string())
    }
}

impl From<MacError> for VaultError {
    fn from(error: MacError) -> Self {
        VaultError::new(ErrorKind::IncorrectSecret, &error.to_string())
    }
}

impl From<PadError> for VaultError {
    fn from(_error: PadError) -> Self {
        VaultError::new(ErrorKind::InvalidFormat, "Padding error")
    }
}

impl From<UnpadError> for VaultError {
    fn from(_error: UnpadError) -> Self {
        VaultError::new(ErrorKind::InvalidFormat, "Padding error")
    }
}

impl From<InvalidKeyNonceLength> for VaultError {
    fn from(error: InvalidKeyNonceLength) -> Self {
        VaultError::new(ErrorKind::InvalidFormat, &error.to_string())
    }
}
