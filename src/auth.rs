use crate::error::AuthError;
use bech32::{self, u5, ToBase32};
#[cfg(not(target_arch = "wasm32"))]
use cosmwasm_crypto::secp256k1_verify;
use cosmwasm_std::{Addr, Env, MessageInfo, Timestamp};
#[cfg(target_arch = "wasm32")]
use cosmwasm_std::{Api, ExternalApi};
use ripemd::{Digest, Ripemd160};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::str::from_utf8;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
/// some message along with signed authorization token
pub struct MsgWithAuth<T> {
    pub authorization: Authorization,
    pub message: T,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
/// an ADR-36 signed document along with a signature and pubkey of the signer
pub struct Authorization {
    pub document: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Deserialize, Clone, Debug)]
/// a message with extracted and validated auth token
pub struct Authorized<S, T> {
    pub auth_token: AuthToken<S>,
    pub message: T,
}

#[derive(Deserialize, Clone, Debug)]
/// auth token including addresses of signer and agent, expiration time, and any metadata
pub struct AuthToken<T> {
    pub user: Addr,
    pub agent: Addr,
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
    signer: Addr,
    data: String,
}

/// authorize a message
///
/// takes a message with a signed and encoded auth token, and returns the message along
/// with the validated and decoded auth token.
pub fn authorize<M, A: DeserializeOwned>(
    message: MsgWithAuth<M>,
    info: &MessageInfo,
    env: &Env,
) -> Result<Authorized<A, M>, AuthError> {
    Ok(Authorized {
        message: message.message,
        auth_token: validate(message.authorization, &info.sender, env.block.time)?,
    })
}

/// validate a signed authorization token
///
/// this will ensure that the token is signed by the right address, provided by the right
/// address, and unexpired, and will return the decoded token from within the document if
/// it is valid.
pub fn validate<A: DeserializeOwned>(
    authorization: Authorization,
    provider: &Addr,
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
    validate_token_user(&auth_token, signer)?;
    validate_token_agent(&auth_token, provider)?;

    Ok(auth_token)
}

/// grab the token from inside the SignDoc
fn extract_token<A: DeserializeOwned>(document: &SignDoc) -> Result<AuthToken<A>, AuthError> {
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

/// check that the token is signed by the specified user
fn validate_token_user<A>(token: &AuthToken<A>, signer: &Addr) -> Result<bool, AuthError> {
    if token.user == *signer {
        Ok(true)
    } else {
        Err(AuthError::TokenUserMismatch)
    }
}

/// check that the agent address in the token is the one we expect
fn validate_token_agent<A>(token: &AuthToken<A>, agent: &Addr) -> Result<bool, AuthError> {
    if token.agent == *agent {
        Ok(true)
    } else {
        Err(AuthError::TokenAgentMismatch)
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

    #[cfg(target_arch = "wasm32")]
    let verification = {
        let api = ExternalApi {};
        api.secp256k1_verify(document_hash, signature, pubkey)
    };

    #[cfg(not(target_arch = "wasm32"))]
    let verification = secp256k1_verify(document_hash, signature, pubkey);

    if let Ok(true) = verification {
        Ok(true)
    } else {
        Err(AuthError::InvalidSignature)
    }
}

/// check that the stated signer corresponds to the given public key
fn validate_signer_pubkey(address: &Addr, pubkey: Vec<u8>) -> Result<bool, AuthError> {
    let (_hrp, data, _variant) = bech32::decode(address.as_str())?;
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
