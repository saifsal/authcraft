//! OAuth 2.0 authorization-code + PKCE and OpenID Connect (ADR 0005, ADR 0006).
//!
//! Educational use only. Stub login and in-memory stores are intentional.

#![forbid(unsafe_code)]

pub mod client;
pub mod code;
pub mod denylist;
pub mod error;
pub mod id_token;
pub mod keyring;
pub mod par;
pub mod pkce;
pub mod refresh;
pub mod server;
pub mod token;

pub use client::{Client, ClientRegistry};
pub use error::OAuthError;
pub use id_token::{at_hash_eddsa, scope_has_openid};
pub use server::{
    AuthorizationServer, AuthorizationSuccess, AuthorizeRequest, Introspection, LoginSubject,
    ParSuccess, PendingAuthorization, ServerConfig, TokenRequest, TokenSuccess, TokenTypeHint,
    UserInfo,
};
