//! OAuth 2.0 authorization-code + PKCE (S256) for authcraft M1 (ADR 0005).
//!
//! Educational use only. Stub login and in-memory stores are intentional.

#![forbid(unsafe_code)]

pub mod client;
pub mod code;
pub mod error;
pub mod pkce;
pub mod server;
pub mod token;

pub use client::{Client, ClientRegistry};
pub use error::OAuthError;
pub use server::{
    AuthorizationServer, AuthorizationSuccess, AuthorizeRequest, PendingAuthorization,
    ServerConfig, TokenRequest, TokenSuccess,
};
