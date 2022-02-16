use crate::error::AuthError;
use bech32::{self, u5, ToBase32};
use cosmwasm_std::Timestamp;
use cosmwasm_crypto::secp256k1_verify;
use ripemd::{Digest, Ripemd160};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::Sha256;
use std::str::from_utf8;

#[derive(Deserialize, Clone, Debug)]
/// some message along with signed authorization token
pub struct MessageWithAuthorization<T> {
    pub authorization: Authorization,
    pub message: T,
}

#[derive(Deserialize, Clone, Debug)]
/// an ADR-36 signed document along with a signature and pubkey of the signer
pub struct Authorization {
    pub document: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Deserialize, Clone, Debug)]
/// a message with extracted and validated auth token
pub struct AuthorizedMessage<S, T> {
    pub auth_token: AuthToken<S>,
    pub message: T,
}

#[derive(Deserialize, Clone, Debug)]
/// auth token including address of the signer, expiration time, and any metadata
pub struct AuthToken<T> {
    pub address: String,
    pub expires: u64,
    pub meta: T,
}

#[derive(Deserialize)]
struct SignDoc {
    msgs: [SignMessage; 1],
}

#[derive(Deserialize)]
struct SignMessage {
    value: SignValue,
}

#[derive(Deserialize)]
struct SignValue {
    signer: String,
    data: String,
}

/// authorize a message
///
/// takes a message with a signed and encoded auth token, and returns the message along
/// with the validated and decoded auth token.
pub fn authorize<M, A: DeserializeOwned>(
    message: MessageWithAuthorization<M>,
    block_time: Timestamp,
) -> Result<AuthorizedMessage<A, M>, AuthError> {
    Ok(AuthorizedMessage {
        message: message.message,
        auth_token: validate(message.authorization, block_time)?,
    })
}

/// validate a signed authorization token
///
/// this will ensure that the token is signed by the right address and has not expired
/// and will return the decoded token from within the document if it is valid
pub fn validate<A: DeserializeOwned>(
    authorization: Authorization,
    block_time: Timestamp,
) -> Result<AuthToken<A>, AuthError> {
    let pubkey = base64::decode(authorization.pubkey)?;
    let document = base64::decode(authorization.document)?;
    let signature = base64::decode(authorization.signature)?;
    validate_document_signature(&document, &signature, &pubkey)?;

    let document = from_utf8(&document)?;
    let document: SignDoc = serde_json_wasm::from_str(document)?;
    let signer = &document.msgs[0].value.signer;
    validate_signer_pubkey(signer, pubkey)?;

    let auth_token = extract_token(&document)?;
    validate_token_expires(&auth_token, block_time)?;
    validate_token_address(&auth_token, signer)?;

    Ok(auth_token)
}

/// grab the token from inside the SignDoc
fn extract_token<A: DeserializeOwned>(
    document: &SignDoc,
) -> Result<AuthToken<A>, AuthError> {
    let token = &document.msgs[0].value.data;
    let token = base64::decode(token)?;
    let token = from_utf8(&token)?.to_string();
    Ok(serde_json_wasm::from_str(&token)?)
}

/// validate token has not yet expired
fn validate_token_expires<A>(
    token: &AuthToken<A>,
    block_time: Timestamp,
) -> Result<bool, AuthError> {
    if token.expires > block_time.seconds() {
        Ok(true)
    } else {
        Err(AuthError::TokenExpired)
    }
}

/// check that the address in the token is the one we expect
fn validate_token_address<A>(token: &AuthToken<A>, address: &str) -> Result<bool, AuthError> {
    if token.address == *address {
        Ok(true)
    } else {
        Err(AuthError::TokenAddressMismatch)
    }
}

/// check that the signature is valid for this document
fn validate_document_signature(
    document: &[u8],
    signature: &[u8],
    pubkey: &[u8],
) -> Result<bool, AuthError> {
    let mut hasher = Sha256::new();
    hasher.update(&document);
    let document_hash: &[u8] = &hasher.finalize();

    if let Ok(true) = secp256k1_verify(document_hash, signature, pubkey) {
        Ok(true)
    } else {
        Err(AuthError::InvalidSignature)
    }
}

/// check that the stated signer corresponds to the given public key
fn validate_signer_pubkey(address: &str, pubkey: Vec<u8>) -> Result<bool, AuthError> {
    let (_hrp, data, _variant) = bech32::decode(address)?;
    let hashed_pubkey = hash_pubkey(pubkey);
    if data == hashed_pubkey {
        Ok(true)
    } else {
        Err(AuthError::SignerPubkeyMismatch)
    }
}

/// hash pubkey to get the data encoded in bech32 addresses
fn hash_pubkey(pubkey: Vec<u8>) -> Vec<u5> {
    let mut hasher = Sha256::new();
    hasher.update(&pubkey);
    let pubkey = hasher.finalize();
    let mut hasher = Ripemd160::new();
    hasher.update(pubkey);
    hasher.finalize().to_vec().to_base32()
}
