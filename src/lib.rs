//! # cosmwasm off-chain auth
//!
//! a utility that takes an ADR-036 signed document containing an auth token, decodes
//! and verifies it, returning the inner token if it is valid

pub mod error;
pub mod auth;

pub use crate::auth::*;
pub use crate::error::AuthError;
