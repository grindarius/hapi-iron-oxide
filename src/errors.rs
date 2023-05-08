use std::num::ParseIntError;

use base64::{DecodeError, DecodeSliceError};
use thiserror::Error;
use time::error::ComponentRange;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum HapiIronOxideError {
    #[error("password field is empty")]
    PasswordFieldEmpty,
    #[error("password required")]
    PasswordRequired,
    #[error("password too short")]
    PasswordTooShort,
    #[error("function \"normalize\" is not implemented for the type")]
    NormalizeUnimplemented,
    #[error("function \"normalize_unseal\", is not implemented for the type")]
    NormalizeUnsealUnimplemented,
    #[error(
        "invalid encryption algorithm: {0}, the algorithm can only be AES-128-CTR or AES-256-CBC"
    )]
    InvalidEncryptionAlgorithm(String),
    #[error(
        "invalid decryption algorithm: {0}, the algorithm can only be AES-128-CTR or AES-256-CBC"
    )]
    InvalidDecryptionAlgorithm(String),
    #[error("invalid hash algorithm: {0}, the algorithm can only be SHA-256")]
    InvalidHashAlgorithm(String),
    #[error("invalid seal")]
    InvalidSeal,
    #[error("expired seal")]
    ExpiredSeal,
    #[error("invalid seal prefix")]
    InvalidSealPrefix,
    #[error("expiration cannot be parsed to `i128`")]
    ExpirationCannotBeParsed,
    #[error("invalid hmac value")]
    InvalidHmacValue,
    #[error("base64 decode error: {0}")]
    Base64DecodeError(String),
    #[error("parse int error for unix timestamp string: {0}")]
    ParseIntError(String),
    #[error("unix timestamp out of range: {0}")]
    TimestampOutOfRange(String),
    #[error("iv size not equals 16")]
    InvalidIVSize,
    #[error("unpad error")]
    UnpadError,
}

impl From<DecodeError> for HapiIronOxideError {
    fn from(value: DecodeError) -> Self {
        HapiIronOxideError::Base64DecodeError(value.to_string())
    }
}

impl From<DecodeSliceError> for HapiIronOxideError {
    fn from(value: DecodeSliceError) -> Self {
        HapiIronOxideError::Base64DecodeError(value.to_string())
    }
}

impl From<ParseIntError> for HapiIronOxideError {
    fn from(value: ParseIntError) -> Self {
        HapiIronOxideError::ParseIntError(value.to_string())
    }
}

impl From<ComponentRange> for HapiIronOxideError {
    fn from(value: ComponentRange) -> Self {
        HapiIronOxideError::TimestampOutOfRange(value.to_string())
    }
}
