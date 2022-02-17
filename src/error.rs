use cosmwasm_std::{StdError, VerificationError};
#[cfg(not(target_arch = "wasm32"))]
use cosmwasm_crypto::CryptoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("{0}")]
    StdError(#[from] StdError),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("{0}")]
    CryptoError(#[from] CryptoError),

    #[error("{0}")]
    Bech32Error(#[from] bech32::Error),

    #[error("{0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("{0}")]
    VerificationError(#[from] VerificationError),

    #[error("{0}")]
    DecodeJsonError(#[from] serde_json_wasm::de::Error),

    #[error("{0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signer address does not match pubkey")]
    SignerPubkeyMismatch,

    #[error("Token expired")]
    TokenExpired,

    #[error("Token address does not match signer address")]
    TokenAddressMismatch,
}
