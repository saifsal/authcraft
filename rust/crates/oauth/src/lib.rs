//! OAuth 2.0 authorization-code + PKCE, OIDC, and resource-owner authn (ADR 0005–0010).
//!
//! Educational use only. In-memory stores are intentional.

#![forbid(unsafe_code)]

pub mod client;
pub mod code;
pub mod denylist;
pub mod dpop;
pub mod error;
pub mod id_token;
pub mod keyring;
pub mod par;
pub mod pkce;
pub mod refresh;
pub mod server;
pub mod token;
pub mod totp;
pub mod users;
pub mod webauthn_mfa;

pub use client::{Client, ClientRegistry};
pub use error::OAuthError;
pub use id_token::{at_hash_eddsa, scope_has_openid};
pub use server::{
    AuthorizationServer, AuthorizationSuccess, AuthorizeRequest, Introspection, LoginSubject,
    ParSuccess, PendingAuthorization, ServerConfig, TokenRequest, TokenSuccess, TokenTypeHint,
    TotpEnrollment, UserInfo,
};
pub use users::{hash_password, AuthnError, UserRecord, UserStore, DEMO_ALICE_PASSWORD};
